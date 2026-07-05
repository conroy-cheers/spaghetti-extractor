from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .util import sha256_file, write_json


class StageBProvenanceInputError(ValueError):
    pass


_UNDEFINED_REFERENCE_RE = re.compile(r"undefined reference to [`']([^`']+)'")


def stage_b_generate_candidate_provenance(
    *,
    target_name: str,
    skeleton_manifest: Path,
    candidate: Path,
    build_target: str,
    build_compiler: str,
    out: Path,
    functional_report: Path | None = None,
    build_output: str | None = None,
    build_report: Path | None = None,
    target_closure_manifest: Path | None = None,
    fixed_up_sources: list[Path] | tuple[Path, ...] | None = None,
) -> dict[str, Any]:
    skeleton_manifest = Path(skeleton_manifest)
    candidate = Path(candidate)
    payload = _load_json(skeleton_manifest)
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-skeleton-v1":
        raise StageBProvenanceInputError("Stage B candidate provenance requires a stage-b-skeleton-v1 manifest")
    if payload.get("target_name") != target_name:
        raise StageBProvenanceInputError("Stage B skeleton manifest target_name does not match the requested candidate target")
    source = _skeleton_source_output(payload)
    if source is None:
        raise StageBProvenanceInputError("Stage B skeleton manifest must include outputs.source path and sha256")
    if not build_target:
        raise StageBProvenanceInputError("Stage B candidate provenance requires a non-empty build target")
    if not build_compiler:
        raise StageBProvenanceInputError("Stage B candidate provenance requires a non-empty build compiler")
    if not candidate.exists():
        raise StageBProvenanceInputError(f"Stage B candidate binary is not available: {candidate}")
    target_closure_manifest = Path(target_closure_manifest) if target_closure_manifest is not None else None
    target_closure_payload = (
        _load_target_closure_manifest(target_closure_manifest)
        if target_closure_manifest is not None
        else None
    )

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    source_roots = [
        {
            "kind": "stage_b_generated_skeleton",
            "path": str(skeleton_manifest),
            "source": source["path"],
            "source_sha256": source["sha256"],
        }
    ]
    source_roots.extend(_fixed_up_source_roots(fixed_up_sources or (), source))
    build = {
        "target": build_target,
        "compiler": build_compiler,
        "output": build_output or candidate.name,
        "output_sha256": sha256_file(candidate),
    }
    target_import_closure = _target_import_closure(
        target_name,
        payload,
        target_closure_manifest=target_closure_payload,
        target_closure_manifest_path=target_closure_manifest,
    )
    if build_report is not None:
        build["report"] = _candidate_build_report_summary(
            Path(build_report),
            target_name=target_name,
            target_import_closure=target_import_closure,
        )

    provenance = {
        "format": "stage-b-candidate-provenance-v1",
        "target_name": target_name,
        "status": "buildable_skeleton_candidate",
        "skeleton_manifest_sha256": sha256_file(skeleton_manifest),
        "upstream_source_access": False,
        "manual_behavioral_fixups": [],
        "source_roots": source_roots,
        "build": build,
        "functional_tests": _candidate_functional_tests_from_report(functional_report),
    }
    write_json(out / "candidate-provenance.json", provenance)
    return provenance


def _fixed_up_source_roots(
    fixed_up_sources: list[Path] | tuple[Path, ...],
    generated_source: dict[str, str],
) -> list[dict[str, Any]]:
    roots: list[dict[str, Any]] = []
    for path in fixed_up_sources:
        item = Path(path)
        if not item.is_file():
            raise StageBProvenanceInputError(f"Stage B fixed-up source is not available: {item}")
        roots.append(
            {
                "kind": "stage_b_fixed_up_source",
                "path": str(item),
                "source": str(item),
                "source_sha256": sha256_file(item),
                "derived_from": generated_source["path"],
                "derived_from_sha256": generated_source["sha256"],
                "fixup_policy": "compile_and_structure_only",
                "behavioral_fixups": [],
            }
        )
    return roots


def _candidate_functional_tests_from_report(functional_report: Path | None) -> dict[str, Any]:
    if functional_report is None:
        return {
            "status": "not_run",
            "suites": [],
        }

    functional_report = Path(functional_report)
    payload = _load_json(functional_report)
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-functional-report-v1":
        raise StageBProvenanceInputError("Stage B candidate provenance functional report must have format stage-b-functional-report-v1")
    status = str(payload.get("status") or "fail")
    suite = {
        "id": str(payload.get("suite_id") or ""),
        "name": str(payload.get("suite_name") or ""),
        "status": status,
    }
    for key in ("suite_sha256", "suite_case_manifest_sha256"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            suite[key] = value
    coverage = payload.get("coverage")
    if isinstance(coverage, dict):
        for key in ("case_ids_sha256", "source_sha256", "source_revision", "materialized_by"):
            value = coverage.get(key)
            if isinstance(value, str) and value:
                suite[key] = value
    return {
        "status": status,
        "report": str(functional_report),
        "report_sha256": sha256_file(functional_report),
        "suites": [suite],
    }


def _candidate_build_report_summary(
    build_report: Path,
    *,
    target_name: str,
    target_import_closure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = _load_json(build_report)
    if not isinstance(payload, dict):
        raise StageBProvenanceInputError("Stage B candidate build report must be a JSON object")
    linker_flags = _string_list(payload.get("linker_flags"))
    rooted = payload.get("rooted_link_diagnostic") if isinstance(payload.get("rooted_link_diagnostic"), dict) else {}
    rooted_linker_flags = _string_list(rooted.get("linker_flags"))
    all_strings = _json_string_values(payload)
    reference_inputs = _stage_b_reference_build_input_strings(target_name, all_strings)
    source_dependency_policy = _stage_b_source_dependency_policy(
        target_name=target_name,
        reference_inputs=reference_inputs,
        linker_flags=linker_flags,
        rooted_linker_flags=rooted_linker_flags,
    )
    summary = {
        "path": str(build_report),
        "sha256": sha256_file(build_report),
        "format": payload.get("format"),
        "status": payload.get("status"),
        "linker_flags": linker_flags,
        "rooted_linker_flags": rooted_linker_flags,
        "reference_inputs": reference_inputs,
        "source_dependency_policy": source_dependency_policy,
        "target_import_closure": target_import_closure or _empty_target_import_closure(target_name),
    }
    for key in ("generated_target_closure", "generated_import_libraries", "generated_target_dlls"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            summary[key] = value
    standalone = payload.get("standalone_link_diagnostic")
    if isinstance(standalone, dict):
        undefined_symbols = _undefined_reference_symbols(standalone.get("undefined_reference_samples", []))
        target_import_symbols = _target_import_symbol_matches(undefined_symbols, target_import_closure)
        summary["standalone_link_diagnostic"] = {
            "status": standalone.get("status"),
            "returncode": standalone.get("returncode"),
            "unresolved_reference_lines": standalone.get("unresolved_reference_lines"),
            "undefined_symbol_count": len(undefined_symbols),
            "undefined_symbols": undefined_symbols[:100],
            "undefined_symbol_families": _undefined_symbol_families(undefined_symbols),
            "target_import_symbol_count": len(target_import_symbols),
            "target_import_symbols": target_import_symbols[:100],
            "repair_plan": _standalone_link_repair_plan(
                undefined_symbols,
                target_import_symbols,
                target_import_closure=target_import_closure,
            ),
            "undefined_reference_samples": standalone.get("undefined_reference_samples", []),
            "stdout": standalone.get("stdout"),
            "stderr": standalone.get("stderr"),
        }
    return summary


def _load_target_closure_manifest(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-target-closure-skeletons-v1":
        raise StageBProvenanceInputError("Stage B target closure manifest must have format stage-b-target-closure-skeletons-v1")
    return payload


def _target_import_closure(
    target_name: str,
    skeleton_payload: dict[str, Any],
    *,
    target_closure_manifest: dict[str, Any] | None = None,
    target_closure_manifest_path: Path | None = None,
) -> dict[str, Any]:
    original = skeleton_payload.get("original")
    imports = original.get("imports") if isinstance(original, dict) else []
    if not isinstance(imports, list):
        imports = []
    target_imports: dict[str, dict[str, Any]] = {}
    for item in imports:
        if not isinstance(item, dict):
            continue
        dll = str(item.get("dll") or "")
        symbol = item.get("symbol")
        if not dll or not isinstance(symbol, str) or not symbol:
            continue
        if not _dll_is_target_owned(dll, target_name):
            continue
        entry = target_imports.setdefault(
            dll.lower(),
            {
                "dll": dll,
                "symbols": [],
                "symbol_count": 0,
            },
        )
        symbol_entry: dict[str, Any] = {"symbol": _normalized_link_symbol(symbol)}
        if item.get("thunk_rva") is not None:
            symbol_entry["thunk_rva"] = item.get("thunk_rva")
        entry["symbols"].append(symbol_entry)

    dlls = []
    for entry in target_imports.values():
        symbols = sorted(entry["symbols"], key=lambda value: str(value.get("symbol") or ""))
        dlls.append(
            {
                "dll": entry["dll"],
                "symbol_count": len(symbols),
                "symbols": symbols,
            }
        )
    dlls.sort(key=lambda value: str(value["dll"]).lower())
    symbol_count = sum(int(item["symbol_count"]) for item in dlls)
    closure = {
        "status": "incomplete" if dlls else "not_applicable",
        "target_name": target_name,
        "policy": "target-owned imported DLLs must be reimplemented or included in the Stage B validation contract; they are not ordinary external dependencies",
        "dll_count": len(dlls),
        "symbol_count": symbol_count,
        "dlls": dlls,
    }
    if not dlls or target_closure_manifest is None:
        return closure

    generated = _target_closure_generated_representation(
        target_name=target_name,
        required_dlls=dlls,
        manifest=target_closure_manifest,
        manifest_path=target_closure_manifest_path,
    )
    closure["generated_closure"] = generated
    closure["status"] = "satisfied" if generated["status"] == "satisfied" else "incomplete"
    return closure


def _target_closure_generated_representation(
    *,
    target_name: str,
    required_dlls: list[dict[str, Any]],
    manifest: dict[str, Any],
    manifest_path: Path | None,
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    if manifest.get("target_name") != target_name:
        issues.append(
            {
                "category": "target_closure_target_mismatch",
                "expected": target_name,
                "observed": manifest.get("target_name"),
            }
        )

    target_dlls = {str(item).lower() for item in manifest.get("target_dlls", []) if str(item)}
    required_dll_names = {str(item.get("dll") or "").lower() for item in required_dlls}
    missing_dlls = sorted(required_dll_names - target_dlls) if target_dlls else []
    for dll in missing_dlls:
        issues.append({"category": "target_closure_missing_dll", "dll": dll})

    skeletons = _target_closure_skeleton_symbols(manifest, manifest_path, issues)
    symbol_map: dict[str, list[dict[str, Any]]] = {}
    for skeleton in skeletons:
        for symbol in skeleton["symbols"]:
            symbol_map.setdefault(symbol, []).append(
                {
                    "symbol": symbol,
                    "skeleton_manifest": skeleton["manifest"],
                    "target_name": skeleton["target_name"],
                }
            )

    missing_symbols: list[dict[str, Any]] = []
    represented_symbols: list[dict[str, Any]] = []
    for dll in required_dlls:
        dll_name = str(dll.get("dll") or "")
        for item in dll.get("symbols", []):
            if not isinstance(item, dict):
                continue
            symbol = _normalized_link_symbol(str(item.get("symbol") or ""))
            if not symbol:
                continue
            matches = symbol_map.get(symbol, [])
            if matches:
                represented_symbols.append({"dll": dll_name, "symbol": symbol, "matches": matches[:5]})
            else:
                missing_symbols.append({"dll": dll_name, "symbol": symbol})

    if missing_symbols:
        issues.append(
            {
                "category": "target_closure_missing_symbols",
                "count": len(missing_symbols),
                "symbols": missing_symbols[:50],
            }
        )

    status = "satisfied" if not issues and not missing_symbols else "incomplete"
    return {
        "format": "stage-b-target-closure-representation-v1",
        "status": status,
        "manifest": str(manifest_path) if manifest_path is not None else None,
        "manifest_sha256": sha256_file(manifest_path) if manifest_path is not None and manifest_path.is_file() else None,
        "skeletons": skeletons,
        "counts": {
            "required_symbols": sum(
                len(dll.get("symbols", [])) for dll in required_dlls if isinstance(dll.get("symbols"), list)
            ),
            "represented_symbols": len(represented_symbols),
            "missing_symbols": len(missing_symbols),
            "skeletons": len(skeletons),
            "issues": len(issues),
        },
        "represented_symbols": represented_symbols[:100],
        "missing_symbols": missing_symbols[:100],
        "issues": issues,
    }


def _target_closure_skeleton_symbols(
    manifest: dict[str, Any],
    manifest_path: Path | None,
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = manifest.get("skeleton_manifests")
    if not isinstance(rows, list) or not rows:
        issues.append({"category": "target_closure_missing_skeleton_manifests"})
        return []

    skeletons: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, str) or not row:
            issues.append({"category": "target_closure_invalid_skeleton_manifest_path", "index": index})
            continue
        path = Path(row)
        if not path.is_absolute() and manifest_path is not None:
            path = manifest_path.parent / path
        try:
            payload = _load_json(path)
        except StageBProvenanceInputError as exc:
            issues.append({"category": "target_closure_skeleton_unreadable", "path": str(path), "error": str(exc)})
            continue
        if not isinstance(payload, dict) or payload.get("format") != "stage-b-skeleton-v1":
            issues.append({"category": "target_closure_invalid_skeleton_manifest", "path": str(path)})
            continue
        source_policy = payload.get("source_policy") if isinstance(payload.get("source_policy"), dict) else {}
        if source_policy.get("upstream_source_read") is not False:
            issues.append({"category": "target_closure_skeleton_source_policy", "path": str(path)})
        functions_path = _target_closure_functions_path(path, payload)
        functions: list[dict[str, Any]] = []
        if functions_path is None:
            issues.append({"category": "target_closure_missing_functions_output", "path": str(path)})
        else:
            try:
                functions_payload = _load_json(functions_path)
            except StageBProvenanceInputError as exc:
                issues.append({"category": "target_closure_functions_unreadable", "path": str(functions_path), "error": str(exc)})
                functions_payload = {}
            function_rows = functions_payload.get("functions") if isinstance(functions_payload, dict) else None
            if isinstance(function_rows, list):
                functions = [item for item in function_rows if isinstance(item, dict)]
            else:
                issues.append({"category": "target_closure_invalid_functions_output", "path": str(functions_path)})
        symbols = sorted(_target_closure_function_symbols(functions))
        skeletons.append(
            {
                "manifest": str(path),
                "manifest_sha256": sha256_file(path) if path.is_file() else None,
                "target_name": payload.get("target_name"),
                "status": payload.get("status"),
                "implementation_recovery_status": (
                    payload.get("implementation_recovery", {}).get("status")
                    if isinstance(payload.get("implementation_recovery"), dict)
                    else None
                ),
                "source_implements_behavior": (
                    payload.get("implementation_recovery", {}).get("source_implements_behavior")
                    if isinstance(payload.get("implementation_recovery"), dict)
                    else None
                ),
                "functions": len(functions),
                "symbols": symbols,
            }
        )
    return skeletons


def _target_closure_functions_path(manifest_path: Path, payload: dict[str, Any]) -> Path | None:
    outputs = payload.get("outputs") if isinstance(payload.get("outputs"), dict) else {}
    functions = outputs.get("functions") if isinstance(outputs.get("functions"), dict) else {}
    path = functions.get("path")
    if not isinstance(path, str) or not path:
        return None
    result = Path(path)
    if not result.is_absolute():
        result = manifest_path.parent / result
    return result


def _target_closure_function_symbols(functions: list[dict[str, Any]]) -> set[str]:
    symbols: set[str] = set()
    for function in functions:
        for value in [function.get("name"), *(function.get("aliases") if isinstance(function.get("aliases"), list) else [])]:
            if not isinstance(value, str):
                continue
            symbol = _normalized_link_symbol(value)
            if symbol:
                symbols.add(symbol)
    return symbols


def _empty_target_import_closure(target_name: str) -> dict[str, Any]:
    return {
        "status": "not_applicable",
        "target_name": target_name,
        "policy": "target-owned imported DLLs must be reimplemented or included in the Stage B validation contract; they are not ordinary external dependencies",
        "dll_count": 0,
        "symbol_count": 0,
        "dlls": [],
    }


def _target_import_symbol_matches(
    undefined_symbols: list[str],
    target_import_closure: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    symbol_map = _target_import_symbol_map(target_import_closure)
    matches: list[dict[str, Any]] = []
    for symbol in undefined_symbols:
        for entry in symbol_map.get(symbol, []):
            matches.append(dict(entry))
    return matches


def _target_import_symbol_map(target_import_closure: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(target_import_closure, dict):
        return result
    dlls = target_import_closure.get("dlls")
    if not isinstance(dlls, list):
        return result
    for dll in dlls:
        if not isinstance(dll, dict):
            continue
        dll_name = str(dll.get("dll") or "")
        symbols = dll.get("symbols")
        if not isinstance(symbols, list):
            continue
        for item in symbols:
            if not isinstance(item, dict):
                continue
            symbol = _normalized_link_symbol(str(item.get("symbol") or ""))
            if not symbol:
                continue
            entry = {"symbol": symbol, "dll": dll_name}
            if item.get("thunk_rva") is not None:
                entry["thunk_rva"] = item.get("thunk_rva")
            result.setdefault(symbol, []).append(entry)
    return result


def _standalone_link_repair_plan(
    undefined_symbols: list[str],
    target_import_symbols: list[dict[str, Any]],
    *,
    target_import_closure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target_import_names = {str(item.get("symbol")) for item in target_import_symbols if item.get("symbol")}
    items: list[dict[str, Any]] = []
    closure_satisfied = isinstance(target_import_closure, dict) and target_import_closure.get("status") == "satisfied"
    for item in target_import_symbols:
        items.append(
            {
                "category": "target_import_symbol_not_linked" if closure_satisfied else "target_import_symbol",
                "symbol": item.get("symbol"),
                "dll": item.get("dll"),
                "next_action": (
                    "link the generated Stage B target-closure import library/object for this symbol"
                    if closure_satisfied
                    else "generate behavior-bearing Stage B source for this target import or add the imported target DLL to the Stage A/Stage B validation closure"
                ),
            }
        )
    for symbol in undefined_symbols:
        if symbol in target_import_names:
            continue
        items.append(
            {
                "category": "unresolved_external_symbol",
                "symbol": symbol,
                "next_action": "classify the symbol as allowed runtime/import dependency or generate a Stage B implementation",
            }
        )
    counts: dict[str, int] = {}
    for item in items:
        category = str(item["category"])
        counts[category] = counts.get(category, 0) + 1
    if target_import_symbols and closure_satisfied:
        status = "target_import_closure_not_linked"
    elif target_import_symbols:
        status = "blocked_on_target_import_closure"
    else:
        status = "incomplete" if undefined_symbols else "not_applicable"
    return {
        "status": status,
        "counts": counts,
        "items": items[:100],
        "next_actions": _standalone_link_repair_next_actions(status),
    }


def _standalone_link_repair_next_actions(status: str) -> list[str]:
    if status == "blocked_on_target_import_closure":
        return [
            "treat target-owned imported DLLs as part of the Stage B target closure",
            "generate behavior-bearing source for the imported target symbols or validate a same-architecture reimplementation of the target DLLs with Stage A",
            "do not satisfy these references by linking original/reference target import libraries",
        ]
    if status == "target_import_closure_not_linked":
        return [
            "link the candidate against generated Stage B target-closure artifacts instead of original/reference target libraries",
            "keep the generated target closure in the Stage A/Stage B validation evidence package",
        ]
    if status == "incomplete":
        return ["classify unresolved externals and either link allowed dependencies or generate Stage B implementations"]
    return []


def _stage_b_source_dependency_policy(
    *,
    target_name: str,
    reference_inputs: list[str],
    linker_flags: list[str],
    rooted_linker_flags: list[str],
) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, value: str, *, context: str, reason: str) -> None:
        key = (kind, value, context)
        if key in seen:
            return
        seen.add(key)
        violations.append(
            {
                "kind": kind,
                "value": value,
                "context": context,
                "reason": reason,
                "severity": "violated",
            }
        )

    for value in reference_inputs:
        add(
            "reference_target_artifact",
            value,
            context="build_report",
            reason="build input path references an original/reference target artifact",
        )

    for item in _target_library_linkage_flags(target_name, linker_flags, rooted_linker_flags):
        add(
            "target_library_linkage",
            item["value"],
            context=item["context"],
            reason=f"linker flag pulls in the target library for {target_name}",
        )

    return {
        "status": "violated" if violations else "satisfied",
        "allowed_external_dependency_policy": "non-target third-party runtime/import libraries are allowed; original/reference target libraries are not",
        "violations": violations,
        "violation_count": len(violations),
    }


def _target_library_linkage_flags(target_name: str, linker_flags: list[str], rooted_linker_flags: list[str]) -> list[dict[str, str]]:
    aliases = _target_library_aliases(target_name)
    matches: list[dict[str, str]] = []
    for context, flags in (("linker_flags", linker_flags), ("rooted_linker_flags", rooted_linker_flags)):
        for flag in flags:
            if _linker_flag_references_target_library(flag, aliases):
                matches.append({"context": context, "value": flag})
    return matches


def _target_library_aliases(target_name: str) -> set[str]:
    normalized = _library_alias_token(target_name)
    aliases = {normalized} if normalized else set()
    aliases.add(_library_alias_token(target_name.replace("-", "")))
    aliases.add(_library_alias_token(target_name.replace("_", "")))
    if normalized == "jq":
        aliases.update({"jq"})
    if normalized in {"ripgrep", "rg"}:
        aliases.update({"ripgrep", "rg"})
    return {alias for alias in aliases if alias}


def _dll_is_target_owned(dll: str, target_name: str) -> bool:
    aliases = _target_library_aliases(target_name)
    name = Path(str(dll)).name.lower()
    for suffix in (".dll", ".drv", ".ocx"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    token = _library_alias_token(name)
    for alias in aliases:
        if token in {alias, f"lib{alias}"}:
            return True
        if token.startswith(f"lib{alias}") or token.startswith(alias):
            return True
    return False


def _linker_flag_references_target_library(flag: str, aliases: set[str]) -> bool:
    for token in _linker_flag_tokens(flag):
        if token.startswith("-l:"):
            if _library_filename_matches(token[3:], aliases):
                return True
            continue
        if token.startswith("-l") and len(token) > 2:
            if _library_alias_token(token[2:]) in aliases:
                return True
            continue
        if _library_filename_matches(token, aliases):
            return True
    return False


def _linker_flag_tokens(flag: str) -> list[str]:
    tokens: list[str] = []
    for comma_part in str(flag).replace(";", ",").split(","):
        tokens.extend(part for part in comma_part.split() if part)
    return tokens or [str(flag)]


def _library_filename_matches(value: str, aliases: set[str]) -> bool:
    name = Path(value).name.lower()
    if not name:
        return False
    for suffix in (".dll.a", ".lib", ".a", ".dll"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    if name.startswith("lib"):
        name = name[3:]
    return _library_alias_token(name) in aliases


def _library_alias_token(value: str) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def _stage_b_reference_build_input_strings(target_name: str, values: list[str]) -> list[str]:
    markers = [
        f"stage-a-{target_name}",
        f"{target_name}-original",
        f"{target_name}-reference",
        "stage-a-fixtures",
    ]
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if any(marker in value for marker in markers) and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _undefined_reference_symbols(samples: Any) -> list[str]:
    if not isinstance(samples, list):
        return []
    symbols: set[str] = set()
    for item in samples:
        if not isinstance(item, str):
            continue
        match = _UNDEFINED_REFERENCE_RE.search(item)
        if match is None:
            continue
        symbol = _normalized_link_symbol(match.group(1))
        if symbol:
            symbols.add(symbol)
    return sorted(symbols)


def _normalized_link_symbol(symbol: str) -> str:
    value = str(symbol).strip()
    if value.startswith("_") and len(value) > 1 and (value[1].isalpha() or value[1] == "_"):
        value = value[1:]
    return value


def _undefined_symbol_families(symbols: list[str]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for symbol in symbols:
        family = _undefined_symbol_family(symbol)
        counts[family] = counts.get(family, 0) + 1
    return [
        {"family": family, "count": count}
        for family, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _undefined_symbol_family(symbol: str) -> str:
    if symbol.startswith("jq_util_"):
        return "jq_util"
    if symbol.startswith("jq_"):
        return "jq"
    if symbol.startswith("jv_"):
        return "jv"
    if "_" in symbol:
        return symbol.split("_", 1)[0]
    return symbol


def _json_string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(_json_string_values(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_json_string_values(item))
        return result
    return []


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


def _skeleton_source_output(skeleton_payload: dict[str, Any]) -> dict[str, str] | None:
    outputs = skeleton_payload.get("outputs")
    source = outputs.get("source") if isinstance(outputs, dict) else None
    if not isinstance(source, dict):
        return None
    path = source.get("path")
    digest = source.get("sha256")
    if not isinstance(path, str) or not isinstance(digest, str):
        return None
    return {"path": path, "sha256": digest}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StageBProvenanceInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StageBProvenanceInputError(f"invalid JSON in {path}: {exc}") from exc
