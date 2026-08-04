"""Generate compact PE32 interface profiles from a pinned Clang AST."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .external_interface_profiles import EXTERNAL_INTERFACE_PROFILE_FORMAT
from .machine_import_profiles import MachineImportIdentity
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT = (
    "stage-a-external-interface-extraction-spec-v1"
)
_POINTER_ALIAS = re.compile(r"^(?:struct )?(IDirect(?:Draw|Sound)[A-Za-z0-9_]*) \*$")
_DIRECT_DOUBLE_POINTER = re.compile(
    r"^(?:struct )?(IDirect(?:Draw|Sound)[A-Za-z0-9_]*)\s*\*\s*\*$"
)


def extract_external_interface_profile(
    *,
    ast_json: Path,
    spec: Path,
    headers: Sequence[Path],
    out: Path,
) -> dict[str, Any]:
    """Extract vtable order and factory shapes from reviewed SDK headers."""

    spec_path = Path(spec).resolve()
    ast_path = Path(ast_json).resolve()
    payload = _read_object(spec_path, "external-interface extraction spec")
    if payload.get("format") != EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT:
        raise StageAInputError("unsupported external-interface extraction spec")
    profile_id = _nonempty(payload.get("id"), "extraction spec ID")
    if payload.get("model") != "x86-pe32":
        raise StageAInputError("external-interface extraction requires x86-pe32")
    prefixes = tuple(
        _nonempty(value, "interface prefix")
        for value in _array(payload.get("interface_prefixes"), "interface prefixes")
    )
    if not prefixes:
        raise StageAInputError("external-interface extraction has no prefixes")

    expected_headers = {
        _nonempty(_object(raw, "header binding").get("include"), "header include"):
        _nonempty(_object(raw, "header binding").get("sha256"), "header digest")
        for raw in _array(payload.get("headers"), "header bindings")
    }
    supplied_headers = {Path(path).name: Path(path).resolve() for path in headers}
    if set(supplied_headers) != set(expected_headers):
        raise StageAInputError("supplied interface headers differ from the reviewed spec")
    for name, path in supplied_headers.items():
        if sha256_file(path) != expected_headers[name]:
            raise StageAInputError(f"interface header digest mismatch: {name}")

    try:
        ast = json.loads(ast_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read Clang AST: {exc}") from exc
    declarations = tuple(_walk_ast(ast))
    pointer_aliases, output_aliases = _interface_aliases(declarations)
    interfaces = _interfaces(
        declarations, prefixes, pointer_aliases, output_aliases
    )
    known_interfaces = {row["id"] for row in interfaces}
    factories = _factories(
        declarations,
        _array(payload.get("factories"), "factory specifications"),
        pointer_aliases,
        output_aliases,
        known_interfaces,
    )
    result = {
        "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
        "id": profile_id,
        "model": "x86-pe32",
        "status": "complete",
        "provenance": {
            "kind": "pinned_clang_ast_from_reviewed_sdk_headers",
            "generator": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
            "spec": {"path": spec_path.name, "sha256": sha256_file(spec_path)},
            "ast": {"sha256": sha256_file(ast_path)},
            "headers": [
                {
                    "include": name,
                    "sha256": expected_headers[name],
                }
                for name in sorted(expected_headers)
            ],
        },
        "machine_import_signatures": [
            {
                "id": index,
                "import": factory["import"],
                "abi_template": factory["abi_template"],
                "argument_words": factory["argument_words"],
                "override": True,
                "provenance": {
                    "kind": "external_interface_factory_declaration",
                    "declaration": factory["declaration"],
                },
            }
            for index, factory in enumerate(factories)
        ],
        "factories": factories,
        "interfaces": interfaces,
        "counts": {
            "factories": len(factories),
            "interfaces": len(interfaces),
            "methods": sum(len(interface["methods"]) for interface in interfaces),
            "out_interface_effects": sum(
                len(factory["out_interfaces"]) for factory in factories
            ) + sum(
                len(method["out_interfaces"])
                for interface in interfaces
                for method in interface["methods"]
            ),
        },
    }
    write_json(Path(out), result)
    return result


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


def _interface_aliases(
    declarations: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, str], dict[str, str]]:
    qualified_by_name: dict[str, set[str]] = {}
    for declaration in declarations:
        if declaration.get("kind") != "TypedefDecl":
            continue
        name = declaration.get("name")
        type_row = declaration.get("type")
        if not isinstance(name, str) or not isinstance(type_row, Mapping):
            continue
        qualified = type_row.get("qualType")
        if not isinstance(qualified, str):
            continue
        qualified_by_name.setdefault(name, set()).add(qualified.strip())

    pointer_aliases: dict[str, str] = {}
    for name, qualified_types in qualified_by_name.items():
        if len(qualified_types) != 1:
            continue
        matched = _POINTER_ALIAS.fullmatch(next(iter(qualified_types)))
        if matched is None:
            continue
        interface_id = matched.group(1)
        prior = pointer_aliases.get(name)
        if prior is not None and prior != interface_id:
            raise StageAInputError(f"ambiguous interface pointer alias {name}")
        pointer_aliases[name] = interface_id

    output_aliases: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for name, qualified_types in qualified_by_name.items():
            if name in output_aliases or len(qualified_types) != 1:
                continue
            qualified = next(iter(qualified_types))
            direct = _DIRECT_DOUBLE_POINTER.fullmatch(qualified)
            interface_id = direct.group(1) if direct is not None else None
            if interface_id is None:
                pointed = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\*", qualified)
                if pointed is not None:
                    interface_id = pointer_aliases.get(pointed.group(1))
            if interface_id is not None:
                output_aliases[name] = interface_id
                changed = True
    return pointer_aliases, output_aliases


def _interfaces(
    declarations: Sequence[Mapping[str, Any]],
    prefixes: Sequence[str],
    pointer_aliases: Mapping[str, str],
    output_aliases: Mapping[str, str],
) -> list[dict[str, Any]]:
    definitions: dict[str, list[Mapping[str, Any]]] = {}
    for declaration in declarations:
        name = declaration.get("name")
        if (
            declaration.get("kind") != "RecordDecl"
            or not isinstance(name, str)
            or not name.endswith("Vtbl")
            or not any(name.startswith(prefix) for prefix in prefixes)
        ):
            continue
        fields = [
            value
            for value in declaration.get("inner", [])
            if isinstance(value, Mapping) and value.get("kind") == "FieldDecl"
        ]
        if fields:
            definitions.setdefault(name, []).append({"fields": fields})
    result: list[dict[str, Any]] = []
    for vtable in sorted(definitions):
        candidates = definitions[vtable]
        signatures = {
            tuple(
                (
                    field.get("name"),
                    _qualified_type(field, f"{vtable} field"),
                )
                for field in candidate["fields"]
            )
            for candidate in candidates
        }
        if len(signatures) != 1:
            raise StageAInputError(f"ambiguous Clang vtable definition {vtable}")
        fields = candidates[0]["fields"]
        interface_id = vtable[:-4]
        methods = []
        for slot, field in enumerate(fields):
            qualified = _qualified_type(field, f"{vtable} field {slot}")
            parameters = _function_pointer_parameters(qualified)
            if "__attribute__((stdcall))" not in qualified:
                raise StageAInputError(
                    f"{vtable} field {slot} is not a PE32 stdcall method"
                )
            methods.append({
                "name": _nonempty(field.get("name"), f"{vtable} field {slot} name"),
                "slot": slot,
                "offset": slot * 4,
                "abi_template": "pe32-stdcall-v1",
                "argument_words": len(parameters),
                "out_interfaces": _infer_outputs(
                    parameters, pointer_aliases, output_aliases
                ),
                "declaration_type": qualified,
            })
        result.append({"id": interface_id, "vtable": vtable, "methods": methods})
    if not result:
        raise StageAInputError("Clang AST contains no selected interface vtables")
    return result


def _factories(
    declarations: Sequence[Mapping[str, Any]],
    specifications: Sequence[Any],
    pointer_aliases: Mapping[str, str],
    output_aliases: Mapping[str, str],
    known_interfaces: set[str],
) -> list[dict[str, Any]]:
    functions: dict[str, set[str]] = {}
    for declaration in declarations:
        if declaration.get("kind") != "FunctionDecl":
            continue
        name = declaration.get("name")
        if not isinstance(name, str):
            continue
        type_row = declaration.get("type")
        if isinstance(type_row, Mapping) and isinstance(type_row.get("qualType"), str):
            functions.setdefault(name, set()).add(str(type_row["qualType"]))

    result: list[dict[str, Any]] = []
    identities: set[MachineImportIdentity] = set()
    for index, raw in enumerate(specifications):
        specification = _object(raw, f"factory specification {index}")
        declaration = _nonempty(
            specification.get("declaration"), f"factory specification {index} declaration"
        )
        candidates = functions.get(declaration, set())
        if len(candidates) != 1:
            raise StageAInputError(
                f"factory declaration {declaration} is missing or ambiguous"
            )
        qualified = next(iter(candidates))
        if "__attribute__((stdcall))" not in qualified:
            raise StageAInputError(f"factory {declaration} is not PE32 stdcall")
        parameters = _function_parameters(qualified)
        inferred = _infer_outputs(parameters, pointer_aliases, output_aliases)
        expected = [
            {
                "argument_index": _word(
                    _object(value, f"factory {declaration} output").get("argument_index"),
                    f"factory {declaration} output argument",
                ),
                "interface_id": _nonempty(
                    _object(value, f"factory {declaration} output").get("interface_id"),
                    f"factory {declaration} output interface",
                ),
                "write_width": 4,
            }
            for value in _array(
                specification.get("out_interfaces"),
                f"factory {declaration} output interfaces",
            )
        ]
        if expected != inferred:
            raise StageAInputError(
                f"factory {declaration} output specification differs from its AST"
            )
        if any(row["interface_id"] not in known_interfaces for row in expected):
            raise StageAInputError(
                f"factory {declaration} returns an unprofiled interface"
            )
        imported = _object(
            specification.get("import"), f"factory {declaration} import"
        )
        identity = MachineImportIdentity.from_mapping(
            imported, context=f"factory {declaration} import"
        )
        if identity in identities:
            raise StageAInputError(f"duplicate factory import {identity}")
        identities.add(identity)
        result.append({
            "id": _nonempty(specification.get("id"), f"factory {declaration} ID"),
            "import": dict(imported),
            "declaration": declaration,
            "declaration_type": qualified,
            "abi_template": "pe32-stdcall-v1",
            "argument_words": len(parameters),
            "out_interfaces": expected,
        })
    return sorted(
        result,
        key=lambda row: (
            str(_object(row["import"], "factory import").get("dll")),
            str(row["id"]),
        ),
    )


def _infer_outputs(
    parameters: Sequence[str],
    pointer_aliases: Mapping[str, str],
    output_aliases: Mapping[str, str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for argument_index, parameter in enumerate(parameters):
        normalized = " ".join(parameter.replace("const", "").split())
        interface_id: str | None = output_aliases.get(normalized)
        direct = _DIRECT_DOUBLE_POINTER.fullmatch(normalized)
        if direct is not None:
            interface_id = direct.group(1)
        else:
            for alias, candidate in pointer_aliases.items():
                if re.fullmatch(rf"{re.escape(alias)}\s*\*", normalized):
                    interface_id = candidate
                    break
        if interface_id is not None:
            result.append({
                "argument_index": argument_index,
                "interface_id": interface_id,
                "write_width": 4,
            })
    return result


def _function_pointer_parameters(qualified: str) -> tuple[str, ...]:
    marker = "(*)("
    start = qualified.find(marker)
    if start < 0:
        raise StageAInputError(f"unsupported vtable field type: {qualified}")
    return _split_parameters(qualified, start + len(marker))


def _function_parameters(qualified: str) -> tuple[str, ...]:
    start = qualified.find("(")
    if start < 0:
        raise StageAInputError(f"unsupported function type: {qualified}")
    return _split_parameters(qualified, start + 1)


def _split_parameters(qualified: str, start: int) -> tuple[str, ...]:
    depth = 0
    end = None
    for index in range(start, len(qualified)):
        character = qualified[index]
        if character == "(":
            depth += 1
        elif character == ")":
            if depth == 0:
                end = index
                break
            depth -= 1
    if end is None:
        raise StageAInputError(f"unterminated function type: {qualified}")
    body = qualified[start:end].strip()
    if not body or body == "void":
        return ()
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for character in body:
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    parts.append("".join(current).strip())
    if any(not part for part in parts):
        raise StageAInputError(f"empty parameter in function type: {qualified}")
    return tuple(parts)


def _qualified_type(value: Mapping[str, Any], context: str) -> str:
    type_row = value.get("type")
    if not isinstance(type_row, Mapping):
        raise StageAInputError(f"{context} has no type")
    return _nonempty(type_row.get("qualType"), f"{context} qualified type")


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


def _word(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 64:
        raise StageAInputError(f"{context} must be between 0 and 64")
    return value


__all__ = [
    "EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT",
    "extract_external_interface_profile",
]
