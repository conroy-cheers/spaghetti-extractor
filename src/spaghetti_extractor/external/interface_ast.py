"""Generate compact PE32 interface profiles from a pinned Clang AST."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    ExternalInterfaceProfileError,
    InterfaceCallerMemoryFrame,
    InterfaceMemoryArgument,
    SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    parse_interface_local_cell_relation,
    same_library_callback_call_through_effect_json,
    same_library_call_through_effect_json,
)
from .machine_abi import resolve_machine_call_abi
from .machine_import_profiles import MachineImportIdentity
from ..errors import ToolkitInputError
from ..util import sha256_file, write_json


EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT = (
    "spaghetti-extractor-external-interface-extraction-spec-v1"
)
_NAMED_POINTER = re.compile(r"^(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\*$")
_NAMED_DOUBLE_POINTER = re.compile(
    r"^(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\*\s*\*$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def validate_external_interface_extraction_spec(
    value: object,
) -> dict[str, Any]:
    """Validate the one reviewed interface-extraction specification shape."""

    payload = _object(value, "external-interface extraction spec")
    required_fields = {
        "format",
        "id",
        "model",
        "headers",
        "interface_prefixes",
        "factories",
    }
    optional_fields = {
        "effect_model",
        "opaque_resource_types",
        "method_callbacks",
        "method_local_cells",
    }
    if not required_fields <= set(payload) or not set(payload) <= (
        required_fields | optional_fields
    ):
        raise ToolkitInputError("external-interface extraction spec fields differ")
    if payload.get("format") != EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT:
        raise ToolkitInputError("unsupported external-interface extraction spec")
    _nonempty(payload.get("id"), "extraction spec ID")
    if payload.get("model") != "x86-pe32":
        raise ToolkitInputError("external-interface extraction requires x86-pe32")
    if payload.get("effect_model") != SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL:
        raise ToolkitInputError(
            "external-interface extraction does not opt into the supported "
            "same-library call-through effect model"
        )

    header_names: list[str] = []
    for index, raw in enumerate(_array(payload.get("headers"), "header bindings")):
        row = _object(raw, f"header binding {index}")
        if set(row) != {"include", "sha256"}:
            raise ToolkitInputError(f"header binding {index} fields differ")
        header_names.append(_nonempty(row.get("include"), "header include"))
        digest = row.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ToolkitInputError(f"header binding {index} digest is invalid")
    if not header_names or len(header_names) != len(set(header_names)):
        raise ToolkitInputError("header bindings are empty or duplicated")

    prefixes = [
        _nonempty(raw, "interface prefix")
        for raw in _array(payload.get("interface_prefixes"), "interface prefixes")
    ]
    if not prefixes or len(prefixes) != len(set(prefixes)):
        raise ToolkitInputError("interface prefixes are empty or duplicated")
    opaque_types = [
        _nonempty(raw, "opaque resource type")
        for raw in _array(
            payload.get("opaque_resource_types", []), "opaque resource types"
        )
    ]
    if len(opaque_types) != len(set(opaque_types)):
        raise ToolkitInputError("opaque resource types are duplicated")

    _callback_specs(payload)
    _method_local_cell_specs(payload)
    factory_ids: set[str] = set()
    factory_imports: set[MachineImportIdentity] = set()
    for index, raw in enumerate(
        _array(payload.get("factories"), "factory specifications")
    ):
        row = _object(raw, f"factory specification {index}")
        if set(row) != {"id", "import", "declaration", "out_interfaces"}:
            raise ToolkitInputError(f"factory specification {index} fields differ")
        factory_id = _nonempty(row.get("id"), f"factory specification {index} ID")
        if factory_id in factory_ids:
            raise ToolkitInputError("factory specification IDs are duplicated")
        factory_ids.add(factory_id)
        identity = MachineImportIdentity.from_mapping(
            _object(row.get("import"), f"factory specification {index} import"),
            context=f"factory specification {index} import",
        )
        if identity in factory_imports:
            raise ToolkitInputError("factory specification imports are duplicated")
        factory_imports.add(identity)
        _nonempty(
            row.get("declaration"), f"factory specification {index} declaration"
        )
        outputs = _array(
            row.get("out_interfaces"),
            f"factory specification {index} output interfaces",
        )
        if not outputs:
            raise ToolkitInputError(
                f"factory specification {index} has no output interfaces"
            )
        for output_index, raw_output in enumerate(outputs):
            output = _object(
                raw_output,
                f"factory specification {index} output {output_index}",
            )
            if set(output) != {"argument_index", "interface_id"}:
                raise ToolkitInputError(
                    f"factory specification {index} output {output_index} fields differ"
                )
            _word(
                output.get("argument_index"),
                f"factory specification {index} output argument",
            )
            _nonempty(
                output.get("interface_id"),
                f"factory specification {index} output interface",
            )
    return dict(payload)


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
    payload = validate_external_interface_extraction_spec(
        _read_object(spec_path, "external-interface extraction spec")
    )
    profile_id = _nonempty(payload.get("id"), "extraction spec ID")
    if payload.get("model") != "x86-pe32":
        raise ToolkitInputError("external-interface extraction requires x86-pe32")
    if payload.get("effect_model") != SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL:
        raise ToolkitInputError(
            "external-interface extraction does not opt into the supported "
            "same-library call-through effect model"
        )
    prefixes = tuple(
        _nonempty(value, "interface prefix")
        for value in _array(payload.get("interface_prefixes"), "interface prefixes")
    )
    if not prefixes:
        raise ToolkitInputError("external-interface extraction has no prefixes")

    expected_headers = {
        _nonempty(
            _object(raw, "header binding").get("include"), "header include"
        ): _nonempty(_object(raw, "header binding").get("sha256"), "header digest")
        for raw in _array(payload.get("headers"), "header bindings")
    }
    supplied_headers = {Path(path).name: Path(path).resolve() for path in headers}
    if set(supplied_headers) != set(expected_headers):
        raise ToolkitInputError(
            "supplied interface headers differ from the reviewed spec"
        )
    for name, path in supplied_headers.items():
        if sha256_file(path) != expected_headers[name]:
            raise ToolkitInputError(f"interface header digest mismatch: {name}")

    try:
        ast = json.loads(ast_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read Clang AST: {exc}") from exc
    declarations = tuple(_walk_ast(ast))
    type_aliases = _type_aliases(declarations)
    opaque_resource_types = _opaque_resource_types(payload, declarations)
    pointer_aliases, output_aliases = _interface_aliases(declarations, prefixes)
    callback_aliases = _callback_aliases(
        declarations,
        prefixes=prefixes,
        pointer_aliases=pointer_aliases,
        type_aliases=type_aliases,
    )
    callback_specs = _callback_specs(payload)
    used_callback_specs: set[tuple[str, str, int]] = set()
    local_cell_specs = _method_local_cell_specs(payload)
    used_local_cell_specs: set[tuple[str, str, int]] = set()
    interfaces = _interfaces(
        declarations,
        prefixes,
        pointer_aliases,
        output_aliases,
        callback_aliases,
        callback_specs,
        used_callback_specs,
        local_cell_specs,
        used_local_cell_specs,
        type_aliases,
        opaque_resource_types,
    )
    unused_callback_specs = sorted(set(callback_specs) - used_callback_specs)
    if unused_callback_specs:
        raise ToolkitInputError(
            "callback specifications do not match pinned AST methods: "
            + ", ".join(
                f"{interface}::{method} argument {argument}"
                for interface, method, argument in unused_callback_specs
            )
        )
    unused_local_cell_specs = sorted(set(local_cell_specs) - used_local_cell_specs)
    if unused_local_cell_specs:
        raise ToolkitInputError(
            "local-cell specifications do not match pinned AST methods: "
            + ", ".join(
                f"{interface}::{method} argument {argument}"
                for interface, method, argument in unused_local_cell_specs
            )
        )
    known_interfaces = {row["id"] for row in interfaces}
    factories = _factories(
        declarations,
        _array(payload.get("factories"), "factory specifications"),
        prefixes,
        pointer_aliases,
        output_aliases,
        known_interfaces,
        type_aliases,
        opaque_resource_types,
    )
    vtable_sizes = {
        interface["id"]: len(interface["methods"]) * 4 for interface in interfaces
    }
    result = {
        "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
        "id": profile_id,
        "model": "x86-pe32",
        "status": "complete",
        "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        "opaque_resource_types": sorted(opaque_resource_types),
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
            _factory_machine_signature(index, factory, vtable_sizes)
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
            )
            + sum(
                len(method["out_interfaces"])
                for interface in interfaces
                for method in interface["methods"]
            ),
            "callback_methods": sum(
                method.get("callback_effect") == "explicit"
                for interface in interfaces
                for method in interface["methods"]
            ),
            "incomplete_callback_methods": sum(
                method.get("callback_contract_status") == "incomplete"
                for interface in interfaces
                for method in interface["methods"]
            ),
        },
    }
    write_json(Path(out), result)
    return result


def _factory_machine_signature(
    index: int,
    factory: Mapping[str, Any],
    vtable_sizes: Mapping[str, int],
) -> dict[str, Any]:
    outputs = [
        {
            **dict(output),
            "object_size": 4,
            "vtable_size": vtable_sizes[str(output["interface_id"])],
            "nullable": True,
            "success_condition": "hresult_succeeded_eax",
        }
        for output in factory["out_interfaces"]
    ]
    return {
        "id": index,
        "import": factory["import"],
        "abi_template": factory["abi_template"],
        "machine_abi": dict(_object(factory["machine_abi"], "factory machine ABI")),
        "argument_words": factory["argument_words"],
        "override": True,
        "result_register_relations": [{"register": "eax", "relation": "exact"}],
        **same_library_call_through_effect_json(),
        "caller_memory_frame": dict(
            _object(factory["caller_memory_frame"], "factory caller-memory frame")
        ),
        "out_interface_relations": outputs,
        "provenance": {
            "kind": "external_interface_factory_declaration",
            "declaration": factory["declaration"],
        },
    }


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
    prefixes: Sequence[str],
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
        matched = _NAMED_POINTER.fullmatch(next(iter(qualified_types)))
        if matched is None:
            continue
        interface_id = matched.group(1)
        if not _selected_interface(interface_id, prefixes):
            continue
        prior = pointer_aliases.get(name)
        if prior is not None and prior != interface_id:
            raise ToolkitInputError(f"ambiguous interface pointer alias {name}")
        pointer_aliases[name] = interface_id

    output_aliases: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for name, qualified_types in qualified_by_name.items():
            if name in output_aliases or len(qualified_types) != 1:
                continue
            qualified = next(iter(qualified_types))
            direct = _NAMED_DOUBLE_POINTER.fullmatch(qualified)
            interface_id = (
                direct.group(1)
                if direct is not None and _selected_interface(direct.group(1), prefixes)
                else None
            )
            if interface_id is None:
                pointed = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\*", qualified)
                if pointed is not None:
                    interface_id = pointer_aliases.get(pointed.group(1))
            if interface_id is not None:
                output_aliases[name] = interface_id
                changed = True
    return pointer_aliases, output_aliases


def _type_aliases(
    declarations: Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    candidates: dict[str, set[str]] = {}
    for declaration in declarations:
        if declaration.get("kind") != "TypedefDecl":
            continue
        name = declaration.get("name")
        type_row = declaration.get("type")
        qualified = type_row.get("qualType") if isinstance(type_row, Mapping) else None
        if isinstance(name, str) and name and isinstance(qualified, str):
            candidates.setdefault(name, set()).add(qualified.strip())
    return {
        name: next(iter(values))
        for name, values in candidates.items()
        if len(values) == 1
    }


def _callback_aliases(
    declarations: Sequence[Mapping[str, Any]],
    *,
    prefixes: Sequence[str],
    pointer_aliases: Mapping[str, str],
    type_aliases: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for declaration in declarations:
        if declaration.get("kind") != "TypedefDecl":
            continue
        name = declaration.get("name")
        type_row = declaration.get("type")
        if not isinstance(name, str) or not isinstance(type_row, Mapping):
            continue
        qualified = type_row.get("qualType")
        if not isinstance(qualified, str) or "(*)(" not in qualified:
            continue
        parameters = _function_pointer_parameters(qualified)
        callback_result = _callback_result(
            qualified.split("(*)", 1)[0].strip(), type_aliases
        )
        arguments: list[dict[str, Any]] = []
        for argument_index, parameter in enumerate(parameters):
            normalized = " ".join(parameter.replace("const", "").split())
            interface_id = pointer_aliases.get(normalized)
            if interface_id is None:
                direct = _NAMED_POINTER.fullmatch(normalized)
                if direct is not None and _selected_interface(
                    direct.group(1), prefixes
                ):
                    interface_id = direct.group(1)
            if interface_id is not None:
                arguments.append(
                    {
                        "argument_index": argument_index,
                        "kind": "interface_object",
                        "interface_id": interface_id,
                    }
                )
        result[name] = {
            "declaration_type": qualified,
            "argument_words": len(parameters),
            "abi_supported": (
                "__attribute__((stdcall))" in qualified and callback_result is not None
            ),
            "result": callback_result,
            "arguments": arguments,
        }
    return result


_PE32_WORD_RESULT_TYPES = frozenset(
    {
        "BOOL",
        "DWORD",
        "HRESULT",
        "INT",
        "LONG",
        "LRESULT",
        "NTSTATUS",
        "ULONG",
        "UINT",
        "UINT32",
        "ULONG32",
        "LONG32",
        "WPARAM",
        "LPARAM",
        "int",
        "long",
        "signed int",
        "signed long",
        "unsigned",
        "unsigned int",
        "unsigned long",
    }
)


def _callback_result(
    declared: str, type_aliases: Mapping[str, str]
) -> dict[str, str] | None:
    """Classify callback results with an exact PE32 register transport."""

    current = " ".join(declared.split())
    seen: set[str] = set()
    for _ in range(16):
        normalized = re.sub(r"\b(?:const|volatile|restrict)\b", "", current)
        normalized = " ".join(normalized.split())
        if normalized == "void":
            return {"kind": "void"}
        if "*" in normalized or normalized in _PE32_WORD_RESULT_TYPES:
            return {"kind": "word", "register": "eax"}
        if normalized in seen:
            return None
        seen.add(normalized)
        target = type_aliases.get(normalized)
        if target is None:
            return None
        current = target
    return None


def _callback_specs(
    payload: Mapping[str, Any],
) -> dict[tuple[str, str, int], dict[str, Any]]:
    result: dict[tuple[str, str, int], dict[str, Any]] = {}
    for index, raw in enumerate(
        _array(payload.get("method_callbacks", []), "method callback specifications")
    ):
        row = _object(raw, f"method callback specification {index}")
        interface_id = _nonempty(
            row.get("interface_id"),
            f"method callback specification {index} interface",
        )
        method = _nonempty(
            row.get("method"), f"method callback specification {index} method"
        )
        argument = _word(
            row.get("argument_index"),
            f"method callback specification {index} argument",
        )
        lifetime = _nonempty(
            row.get("lifetime"),
            f"method callback specification {index} lifetime",
        )
        nullable = row.get("nullable")
        if not isinstance(nullable, bool):
            raise ToolkitInputError(
                f"method callback specification {index} nullable must be boolean"
            )
        argument_origins: list[dict[str, Any]] = []
        for argument_origin_index, raw_origin in enumerate(
            _array(
                row.get("argument_origins", []),
                f"method callback specification {index} argument origins",
            )
        ):
            origin = _object(
                raw_origin,
                f"method callback specification {index} argument origin "
                f"{argument_origin_index}",
            )
            if set(origin) != {"argument_index", "kind", "interface_id"}:
                raise ToolkitInputError(
                    f"method callback specification {index} argument origin "
                    f"{argument_origin_index} has invalid fields"
                )
            argument_index = _word(
                origin.get("argument_index"),
                f"method callback specification {index} callback argument",
            )
            interface_id_origin = _nonempty(
                origin.get("interface_id"),
                f"method callback specification {index} callback interface",
            )
            if origin.get("kind") != "interface_object":
                raise ToolkitInputError(
                    f"method callback specification {index} argument origin "
                    "kind is unsupported"
                )
            argument_origins.append(
                {
                    "argument_index": argument_index,
                    "kind": "interface_object",
                    "interface_id": interface_id_origin,
                }
            )
        if len({row["argument_index"] for row in argument_origins}) != len(
            argument_origins
        ):
            raise ToolkitInputError(
                f"method callback specification {index} duplicates an argument origin"
            )
        key = (interface_id, method, argument)
        if key in result:
            raise ToolkitInputError(f"duplicate method callback specification {key}")
        result[key] = {
            "lifetime": lifetime,
            "nullable": nullable,
            "argument_origins": tuple(argument_origins),
        }
    return result


def _method_callback_contract(
    *,
    interface_id: str,
    method_name: str,
    parameters: Sequence[str],
    callback_aliases: Mapping[str, Mapping[str, Any]],
    callback_specs: Mapping[tuple[str, str, int], Mapping[str, Any]],
    used_callback_specs: set[tuple[str, str, int]],
) -> dict[str, Any] | None:
    callbacks: list[tuple[int, Mapping[str, Any]]] = []
    for argument_index, parameter in enumerate(parameters):
        normalized = " ".join(parameter.replace("const", "").split())
        alias = callback_aliases.get(normalized)
        if alias is not None:
            callbacks.append((argument_index, alias))
    if not callbacks:
        return None
    blockers: list[str] = []
    source: dict[str, Any] | None = None
    callback_abi: dict[str, Any] | None = None
    lifetime: str | None = None
    specification: Mapping[str, Any] | None = None
    declared_arguments: tuple[dict[str, Any], ...] = ()
    if len(callbacks) != 1:
        blockers.append("multiple_callback_parameters_unsupported")
    else:
        argument_index, alias = callbacks[0]
        source = {"kind": "argument_word", "argument": argument_index}
        specification = callback_specs.get((interface_id, method_name, argument_index))
        if specification is None:
            blockers.append("callback_lifetime_and_nullability_unspecified")
            nullable = False
        else:
            used_callback_specs.add((interface_id, method_name, argument_index))
            lifetime = str(specification["lifetime"])
            nullable = bool(specification["nullable"])
            declared_arguments = tuple(
                dict(argument) for argument in specification.get("argument_origins", ())
            )
            inferred_arguments = tuple(
                dict(argument) for argument in alias.get("arguments", ())
            )
            if any(
                argument not in inferred_arguments for argument in declared_arguments
            ):
                raise ToolkitInputError(
                    f"{interface_id}::{method_name} callback argument protocol "
                    "contradicts the pinned AST type"
                )
        if not alias.get("abi_supported"):
            blockers.append("callback_machine_abi_unsupported")
        else:
            argument_words = int(alias["argument_words"])
            callback_abi = {
                "kind": "generic_callback",
                "argument_words": argument_words,
                "stack_cleanup_bytes": argument_words * 4,
                "nullable": nullable,
                "result": dict(alias["result"]),
            }
    status = "complete" if not blockers else "incomplete"
    return {
        "source": source,
        "abi": callback_abi,
        "lifetime": lifetime,
        "status": status,
        "blockers": tuple(blockers),
        "arguments": (
            declared_arguments
            if len(callbacks) == 1 and specification is not None
            else ()
        ),
    }


def _interfaces(
    declarations: Sequence[Mapping[str, Any]],
    prefixes: Sequence[str],
    pointer_aliases: Mapping[str, str],
    output_aliases: Mapping[str, str],
    callback_aliases: Mapping[str, Mapping[str, Any]],
    callback_specs: Mapping[tuple[str, str, int], Mapping[str, Any]],
    used_callback_specs: set[tuple[str, str, int]],
    local_cell_specs: Mapping[tuple[str, str, int], Mapping[str, Any]],
    used_local_cell_specs: set[tuple[str, str, int]],
    type_aliases: Mapping[str, str],
    opaque_resource_types: frozenset[str],
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
            raise ToolkitInputError(f"ambiguous Clang vtable definition {vtable}")
        fields = candidates[0]["fields"]
        interface_id = vtable[:-4]
        methods = []
        for slot, field in enumerate(fields):
            qualified = _qualified_type(field, f"{vtable} field {slot}")
            parameters = _function_pointer_parameters(qualified)
            if "__attribute__((stdcall))" not in qualified:
                raise ToolkitInputError(
                    f"{vtable} field {slot} is not a PE32 stdcall method"
                )
            method_name = _nonempty(field.get("name"), f"{vtable} field {slot} name")
            callback_contract = _method_callback_contract(
                interface_id=interface_id,
                method_name=method_name,
                parameters=parameters,
                callback_aliases=callback_aliases,
                callback_specs=callback_specs,
                used_callback_specs=used_callback_specs,
            )
            outputs = _infer_outputs(
                parameters, prefixes, pointer_aliases, output_aliases
            )
            argument_interfaces = _infer_argument_interfaces(
                parameters,
                prefixes=prefixes,
                pointer_aliases=pointer_aliases,
                type_aliases=type_aliases,
                output_indices={int(output["argument_index"]) for output in outputs},
            )
            caller_memory_frame = _caller_memory_frame(
                parameters,
                type_aliases=type_aliases,
                interface_pointer_aliases=pointer_aliases,
                callback_aliases=callback_aliases,
                opaque_resource_types=opaque_resource_types,
                output_indices={int(output["argument_index"]) for output in outputs},
                receiver_index=0,
            )
            local_cells = _selected_method_local_cells(
                interface_id=interface_id,
                method_name=method_name,
                argument_words=len(parameters),
                caller_memory_frame=caller_memory_frame,
                specifications=local_cell_specs,
                used=used_local_cell_specs,
            )
            methods.append(
                {
                    "name": method_name,
                    "slot": slot,
                    "offset": slot * 4,
                    **_machine_call_contract(
                        callback_contract,
                        caller_memory_frame=caller_memory_frame,
                    ),
                    "argument_words": len(parameters),
                    "out_interfaces": outputs,
                    "argument_interfaces": argument_interfaces,
                    **({"local_cells": local_cells} if local_cells else {}),
                    "declaration_type": qualified,
                }
            )
        result.append({"id": interface_id, "vtable": vtable, "methods": methods})
    if not result:
        raise ToolkitInputError("Clang AST contains no selected interface vtables")
    return result


def _factories(
    declarations: Sequence[Mapping[str, Any]],
    specifications: Sequence[Any],
    prefixes: Sequence[str],
    pointer_aliases: Mapping[str, str],
    output_aliases: Mapping[str, str],
    known_interfaces: set[str],
    type_aliases: Mapping[str, str],
    opaque_resource_types: frozenset[str],
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
            specification.get("declaration"),
            f"factory specification {index} declaration",
        )
        candidates = functions.get(declaration, set())
        if len(candidates) != 1:
            raise ToolkitInputError(
                f"factory declaration {declaration} is missing or ambiguous"
            )
        qualified = next(iter(candidates))
        if "__attribute__((stdcall))" not in qualified:
            raise ToolkitInputError(f"factory {declaration} is not PE32 stdcall")
        parameters = _function_parameters(qualified)
        inferred = _infer_outputs(parameters, prefixes, pointer_aliases, output_aliases)
        expected = [
            {
                "argument_index": _word(
                    _object(value, f"factory {declaration} output").get(
                        "argument_index"
                    ),
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
            raise ToolkitInputError(
                f"factory {declaration} output specification differs from its AST"
            )
        if any(row["interface_id"] not in known_interfaces for row in expected):
            raise ToolkitInputError(
                f"factory {declaration} returns an unprofiled interface"
            )
        imported = _object(specification.get("import"), f"factory {declaration} import")
        identity = MachineImportIdentity.from_mapping(
            imported, context=f"factory {declaration} import"
        )
        if identity in identities:
            raise ToolkitInputError(f"duplicate factory import {identity}")
        identities.add(identity)
        result.append(
            {
                "id": _nonempty(specification.get("id"), f"factory {declaration} ID"),
                "import": dict(imported),
                "declaration": declaration,
                "declaration_type": qualified,
                **_machine_call_contract(
                    caller_memory_frame=_caller_memory_frame(
                        parameters,
                        type_aliases=type_aliases,
                        interface_pointer_aliases=pointer_aliases,
                        callback_aliases={},
                        opaque_resource_types=opaque_resource_types,
                        output_indices={
                            int(output["argument_index"]) for output in expected
                        },
                        receiver_index=None,
                    ),
                ),
                "argument_words": len(parameters),
                "out_interfaces": expected,
            }
        )
    return sorted(
        result,
        key=lambda row: (
            str(_object(row["import"], "factory import").get("dll")),
            str(row["id"]),
        ),
    )


def _machine_call_contract(
    callback: Mapping[str, Any] | None = None,
    *,
    caller_memory_frame: Mapping[str, Any],
) -> dict[str, Any]:
    abi = resolve_machine_call_abi("pe32-stdcall-v1")
    if abi is None:  # pragma: no cover - guarded by the static ABI registry
        raise ToolkitInputError("PE32 stdcall machine ABI is unavailable")
    effects = (
        same_library_call_through_effect_json()
        if callback is None
        else same_library_callback_call_through_effect_json(
            source=callback.get("source"),
            abi=callback.get("abi"),
            lifetime=callback.get("lifetime"),
            status=str(callback["status"]),
            blockers=tuple(callback.get("blockers", ())),
            callback_arguments=tuple(callback.get("arguments", ())),
        )
    )
    return {
        "abi_template": abi.template,
        "machine_abi": abi.as_json(),
        **effects,
        "caller_memory_frame": dict(caller_memory_frame),
    }


def _caller_memory_frame(
    parameters: Sequence[str],
    *,
    type_aliases: Mapping[str, str],
    interface_pointer_aliases: Mapping[str, str],
    callback_aliases: Mapping[str, Mapping[str, Any]],
    opaque_resource_types: frozenset[str],
    output_indices: set[int],
    receiver_index: int | None,
) -> dict[str, Any]:
    arguments: list[InterfaceMemoryArgument] = []
    for argument_index, parameter in enumerate(parameters):
        resolved = _resolve_pointer_type(parameter, type_aliases)
        if resolved is None:
            continue
        normalized = " ".join(parameter.replace("const", "").split())
        if argument_index in output_indices:
            role = "caller_memory"
            access = "read_write"
            extent = "fixed_word"
            retention = "during_call"
        elif argument_index == receiver_index or _interface_resource_pointer(
            parameter,
            resolved=resolved,
            interface_pointer_aliases=interface_pointer_aliases,
        ):
            role = "interface_resource"
            access = "read_write"
            extent = "opaque_resource"
            retention = "during_call"
        elif _opaque_resource_pointer(
            parameter,
            resolved=resolved,
            opaque_resource_types=opaque_resource_types,
        ):
            role = "interface_resource"
            access = "read_write"
            extent = "opaque_resource"
            retention = "during_call"
        elif normalized in callback_aliases or "(*)" in resolved:
            role = "callback"
            access = "read"
            extent = "opaque_resource"
            retention = "callback_contract"
        else:
            role = "caller_memory"
            access = "read" if _pointee_is_const(resolved) else "read_write"
            extent = "enclosing_object"
            retention = "during_call"
        arguments.append(
            InterfaceMemoryArgument(
                argument_index=argument_index,
                role=role,
                access=access,
                extent=extent,
                retention=retention,
            )
        )
    return InterfaceCallerMemoryFrame(tuple(arguments)).as_json()


def _method_local_cell_specs(
    payload: Mapping[str, Any],
) -> dict[tuple[str, str, int], Mapping[str, Any]]:
    result: dict[tuple[str, str, int], Mapping[str, Any]] = {}
    for index, raw in enumerate(
        _array(
            payload.get("method_local_cells", []),
            "method local-cell specifications",
        )
    ):
        row = _object(raw, f"method local-cell specification {index}")
        if set(row) != {
            "interface_id",
            "method",
            "argument_index",
            "extent_words",
            "variants",
        }:
            raise ToolkitInputError(
                f"method local-cell specification {index} fields differ"
            )
        interface_id = _nonempty(
            row.get("interface_id"), f"method local-cell {index} interface"
        )
        method = _nonempty(row.get("method"), f"method local-cell {index} method")
        try:
            parsed_relation = parse_interface_local_cell_relation(
                {
                    "argument_index": row.get("argument_index"),
                    "extent_words": row.get("extent_words"),
                    "variants": row.get("variants"),
                },
                context=f"method local-cell specification {index}",
            )
        except ExternalInterfaceProfileError as exc:
            raise ToolkitInputError(str(exc)) from exc
        argument_index = parsed_relation.argument_index
        relation = parsed_relation.as_json()
        key = (interface_id, method, argument_index)
        if key in result:
            raise ToolkitInputError("method local-cell specifications are duplicated")
        result[key] = relation
    return result


def _selected_method_local_cells(
    *,
    interface_id: str,
    method_name: str,
    argument_words: int,
    caller_memory_frame: Mapping[str, Any],
    specifications: Mapping[tuple[str, str, int], Mapping[str, Any]],
    used: set[tuple[str, str, int]],
) -> list[dict[str, Any]]:
    memory_arguments = {
        int(argument["argument_index"]): argument
        for argument in _array(
            caller_memory_frame.get("arguments"),
            "method caller-memory arguments",
        )
        if isinstance(argument, Mapping)
    }
    result: list[dict[str, Any]] = []
    for key in sorted(specifications):
        if key[:2] != (interface_id, method_name):
            continue
        argument_index = key[2]
        memory = memory_arguments.get(argument_index)
        relation = specifications[key]
        if (
            not 0 <= argument_index < argument_words
            or memory is None
            or memory.get("role") != "caller_memory"
            or memory.get("extent") != "enclosing_object"
            or memory.get("retention") != "during_call"
            or (
                any(
                    variant.get("output_word_indices")
                    for variant in _array(
                        relation.get("variants"),
                        "method local-cell footprint variants",
                    )
                    if isinstance(variant, Mapping)
                )
                and memory.get("access") != "read_write"
            )
        ):
            raise ToolkitInputError(
                f"{interface_id}::{method_name} local-cell relation contradicts its AST pointer"
            )
        used.add(key)
        result.append(dict(relation))
    return result


def _opaque_resource_types(
    payload: Mapping[str, Any],
    declarations: Sequence[Mapping[str, Any]],
) -> frozenset[str]:
    raw_types = payload.get("opaque_resource_types", [])
    declared_names = {
        str(declaration["name"])
        for declaration in declarations
        if declaration.get("kind") in {"TypedefDecl", "RecordDecl"}
        and isinstance(declaration.get("name"), str)
    }
    result: set[str] = set()
    for index, raw in enumerate(_array(raw_types, "opaque resource types")):
        name = _nonempty(raw, f"opaque resource type {index}")
        if name in result:
            raise ToolkitInputError(f"duplicate opaque resource type {name}")
        if name not in declared_names:
            raise ToolkitInputError(
                f"opaque resource type is absent from the pinned AST: {name}"
            )
        result.add(name)
    return frozenset(result)


def _opaque_resource_pointer(
    parameter: str,
    *,
    resolved: str,
    opaque_resource_types: frozenset[str],
) -> bool:
    normalized = re.sub(r"\b(?:const|volatile|restrict)\b", "", parameter)
    normalized = " ".join(normalized.split())
    if normalized in opaque_resource_types:
        return True
    direct = _NAMED_POINTER.fullmatch(
        re.sub(r"\b(?:const|volatile|restrict)\b", "", resolved).strip()
    )
    return direct is not None and direct.group(1) in opaque_resource_types


def _resolve_pointer_type(
    parameter: str,
    type_aliases: Mapping[str, str],
) -> str | None:
    current = " ".join(parameter.split())
    seen: set[str] = set()
    for _ in range(16):
        if "*" in current:
            return current
        alias = re.sub(r"\b(?:const|volatile|restrict)\b", "", current)
        alias = " ".join(alias.split())
        if alias in seen:
            return None
        seen.add(alias)
        target = type_aliases.get(alias)
        if target is None:
            return None
        current = " ".join(target.split())
    return None


def _interface_resource_pointer(
    parameter: str,
    *,
    resolved: str,
    interface_pointer_aliases: Mapping[str, str],
) -> bool:
    normalized = re.sub(r"\b(?:const|volatile|restrict)\b", "", parameter)
    normalized = " ".join(normalized.split())
    if normalized in interface_pointer_aliases:
        return True
    direct = _NAMED_POINTER.fullmatch(
        re.sub(r"\b(?:const|volatile|restrict)\b", "", resolved).strip()
    )
    if direct is None:
        return False
    name = direct.group(1)
    return name == "IUnknown" or name in interface_pointer_aliases.values()


def _infer_argument_interfaces(
    parameters: Sequence[str],
    *,
    prefixes: Sequence[str],
    pointer_aliases: Mapping[str, str],
    type_aliases: Mapping[str, str],
    output_indices: set[int],
) -> list[dict[str, Any]]:
    """Preserve exact SDK-declared COM types for method input resources."""

    result: list[dict[str, Any]] = []
    for argument_index, parameter in enumerate(parameters):
        if argument_index in output_indices:
            continue
        normalized = re.sub(r"\b(?:const|volatile|restrict)\b", "", parameter)
        normalized = " ".join(normalized.split())
        interface_id = pointer_aliases.get(normalized)
        resolved = _resolve_pointer_type(parameter, type_aliases)
        if interface_id is None and resolved is not None:
            direct = _NAMED_POINTER.fullmatch(
                re.sub(r"\b(?:const|volatile|restrict)\b", "", resolved).strip()
            )
            if direct is not None and _selected_interface(direct.group(1), prefixes):
                interface_id = direct.group(1)
        if interface_id is not None:
            result.append(
                {
                    "argument_index": argument_index,
                    "interface_id": interface_id,
                }
            )
    return result


def _pointee_is_const(resolved: str) -> bool:
    before_pointer = resolved.split("*", 1)[0]
    return bool(re.search(r"(?:^|\s)const(?:\s|$)", before_pointer))


def _infer_outputs(
    parameters: Sequence[str],
    prefixes: Sequence[str],
    pointer_aliases: Mapping[str, str],
    output_aliases: Mapping[str, str],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for argument_index, parameter in enumerate(parameters):
        normalized = " ".join(parameter.replace("const", "").split())
        interface_id: str | None = output_aliases.get(normalized)
        direct = _NAMED_DOUBLE_POINTER.fullmatch(normalized)
        if direct is not None and _selected_interface(direct.group(1), prefixes):
            interface_id = direct.group(1)
        else:
            for alias, candidate in pointer_aliases.items():
                if re.fullmatch(rf"{re.escape(alias)}\s*\*", normalized):
                    interface_id = candidate
                    break
        if interface_id is not None:
            result.append(
                {
                    "argument_index": argument_index,
                    "interface_id": interface_id,
                    "write_width": 4,
                }
            )
    return result


def _selected_interface(interface_id: str, prefixes: Sequence[str]) -> bool:
    return any(interface_id.startswith(prefix) for prefix in prefixes)


def _function_pointer_parameters(qualified: str) -> tuple[str, ...]:
    marker = "(*)("
    start = qualified.find(marker)
    if start < 0:
        raise ToolkitInputError(f"unsupported vtable field type: {qualified}")
    return _split_parameters(qualified, start + len(marker))


def _function_parameters(qualified: str) -> tuple[str, ...]:
    start = qualified.find("(")
    if start < 0:
        raise ToolkitInputError(f"unsupported function type: {qualified}")
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
        raise ToolkitInputError(f"unterminated function type: {qualified}")
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
        raise ToolkitInputError(f"empty parameter in function type: {qualified}")
    return tuple(parts)


def _qualified_type(value: Mapping[str, Any], context: str) -> str:
    type_row = value.get("type")
    if not isinstance(type_row, Mapping):
        raise ToolkitInputError(f"{context} has no type")
    return _nonempty(type_row.get("qualType"), f"{context} qualified type")


def _read_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read {context}: {exc}") from exc
    return _object(value, context)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ToolkitInputError(f"{context} must be a list")
    return value


def _nonempty(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolkitInputError(f"{context} must be a nonempty string")
    return value


def _word(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 64:
        raise ToolkitInputError(f"{context} must be between 0 and 64")
    return value


__all__ = [
    "EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT",
    "extract_external_interface_profile",
]
