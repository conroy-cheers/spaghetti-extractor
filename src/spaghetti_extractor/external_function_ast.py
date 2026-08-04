"""Generate fixed-arity PE32 import contracts from a pinned Clang AST."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .import_abi import EXPANDED_IMPORT_ABI_FORMAT
from .machine_import_profiles import MachineImportIdentity
from .stage_binary import StageAInputError, _parse_stage_a_pe
from .util import sha256_file, write_json


EXTERNAL_FUNCTION_EXTRACTION_SPEC_FORMAT = (
    "stage-a-external-function-extraction-spec-v1"
)
_ONE_WORD_BUILTINS = frozenset({
    "_Bool",
    "bool",
    "char",
    "float",
    "int",
    "long",
    "short",
    "signed char",
    "signed int",
    "signed long",
    "signed short",
    "unsigned char",
    "unsigned int",
    "unsigned long",
    "unsigned short",
    "wchar_t",
})
_TWO_WORD_BUILTINS = frozenset({
    "double",
    "long long",
    "unsigned long long",
})


def extract_external_function_profile(
    *,
    ast_json: Path,
    spec: Path,
    headers: Sequence[Path],
    original_pe: Path,
    out: Path,
) -> dict[str, Any]:
    """Bind exact named PE imports to unambiguous fixed SDK declarations."""

    spec_path = Path(spec).resolve()
    ast_path = Path(ast_json).resolve()
    original_path = Path(original_pe).resolve()
    payload = _read_object(spec_path, "external-function extraction spec")
    if payload.get("format") != EXTERNAL_FUNCTION_EXTRACTION_SPEC_FORMAT:
        raise StageAInputError("unsupported external-function extraction spec")
    profile_id = _nonempty(payload.get("id"), "extraction spec ID")
    if payload.get("model") != "x86-pe32":
        raise StageAInputError("external-function extraction requires x86-pe32")
    selected_dlls = {
        _nonempty(value, "selected DLL").lower()
        for value in _array(payload.get("dlls"), "selected DLLs")
    }
    if not selected_dlls:
        raise StageAInputError("external-function extraction has no selected DLLs")
    expected_headers = {
        _nonempty(_object(raw, "header binding").get("include"), "header include"):
        _nonempty(_object(raw, "header binding").get("sha256"), "header digest")
        for raw in _array(payload.get("headers"), "header bindings")
    }
    supplied_headers = {Path(path).name: Path(path).resolve() for path in headers}
    if set(supplied_headers) != set(expected_headers):
        raise StageAInputError("supplied function headers differ from the reviewed spec")
    for name, path in supplied_headers.items():
        if sha256_file(path) != expected_headers[name]:
            raise StageAInputError(f"function header digest mismatch: {name}")

    try:
        ast = json.loads(ast_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read Clang AST: {exc}") from exc
    declarations = _function_declarations(_walk_ast(ast))
    binary = _parse_stage_a_pe(original_path)
    try:
        imports = sorted({
            MachineImportIdentity(
                imported.dll.lower(),
                "symbol",
                str(imported.symbol),
            )
            for imported in binary.imports
            if imported.dll.lower() in selected_dlls
            and imported.symbol is not None
        })
        binary_sha256 = binary.sha256
    finally:
        binary.pe.close()

    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for identity in imports:
        candidates = declarations.get(str(identity.value), set())
        if len(candidates) != 1:
            gaps.append({
                "import": _identity_json(identity),
                "code": (
                    "sdk_declaration_missing"
                    if not candidates
                    else "sdk_declaration_ambiguous"
                ),
                "candidate_count": len(candidates),
            })
            continue
        qualified, words = next(iter(candidates))
        if words is None:
            gaps.append({
                "import": _identity_json(identity),
                "code": "sdk_declaration_parameter_width_unsupported",
                "declaration_type": qualified,
            })
            continue
        entries.append({
            "id": len(entries),
            "import": _identity_json(identity),
            "abi_template": "pe32-stdcall-v1",
            "argument_words": words,
            "override": True,
            "provenance": {
                "kind": "exact_named_import_pinned_sdk_declaration",
                "declaration": str(identity.value),
                "declaration_type": qualified,
            },
        })
    result = {
        "format": EXPANDED_IMPORT_ABI_FORMAT,
        "id": profile_id,
        "model": "x86-pe32",
        "status": "complete" if not gaps else "incomplete",
        "provenance": {
            "kind": "pinned_clang_ast_from_reviewed_sdk_headers",
            "generator": EXTERNAL_FUNCTION_EXTRACTION_SPEC_FORMAT,
            "spec": {"path": spec_path.name, "sha256": sha256_file(spec_path)},
            "ast": {"sha256": sha256_file(ast_path)},
            "headers": [
                {"include": name, "sha256": expected_headers[name]}
                for name in sorted(expected_headers)
            ],
            "source_binary": {"sha256": binary_sha256},
        },
        "machine_import_signatures": entries,
        "gaps": gaps,
        "counts": {
            "selected_named_imports": len(imports),
            "fixed_arity_imports": len(entries),
            "gaps": len(gaps),
        },
    }
    write_json(Path(out), result)
    return result


def _function_declarations(
    declarations: Iterable[Mapping[str, Any]],
) -> dict[str, set[tuple[str, int | None]]]:
    result: dict[str, set[tuple[str, int | None]]] = {}
    for declaration in declarations:
        if declaration.get("kind") != "FunctionDecl":
            continue
        name = declaration.get("name")
        type_row = declaration.get("type")
        if not isinstance(name, str) or not isinstance(type_row, Mapping):
            continue
        qualified = type_row.get("qualType")
        if (
            not isinstance(qualified, str)
            or "__attribute__((stdcall))" not in qualified
            or declaration.get("variadic") is True
        ):
            continue
        parameter_words = 0
        supported = True
        for child in declaration.get("inner", []):
            if not isinstance(child, Mapping) or child.get("kind") != "ParmVarDecl":
                continue
            words = _parameter_words(child)
            if words is None:
                supported = False
                break
            parameter_words += words
        result.setdefault(name, set()).add((
            qualified,
            parameter_words if supported else None,
        ))
    return result


def _parameter_words(parameter: Mapping[str, Any]) -> int | None:
    type_row = parameter.get("type")
    if not isinstance(type_row, Mapping):
        return None
    raw = type_row.get("desugaredQualType", type_row.get("qualType"))
    if not isinstance(raw, str):
        return None
    normalized = " ".join(
        raw.replace("const", "").replace("volatile", "").split()
    ).strip()
    if "*" in normalized or normalized.endswith("]"):
        return 1
    if normalized in _ONE_WORD_BUILTINS:
        return 1
    if normalized in _TWO_WORD_BUILTINS:
        return 2
    return None


def _walk_ast(value: Any) -> Iterable[Mapping[str, Any]]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            yield current
            inner = current.get("inner")
            if isinstance(inner, list):
                stack.extend(reversed(inner))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def _identity_json(identity: MachineImportIdentity) -> dict[str, Any]:
    result: dict[str, Any] = {"dll": identity.dll}
    result[identity.kind] = identity.value
    return result


def _read_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc
    return _object(value, context)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    return value


def _nonempty(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    return value


__all__ = [
    "EXTERNAL_FUNCTION_EXTRACTION_SPEC_FORMAT",
    "extract_external_function_profile",
]
