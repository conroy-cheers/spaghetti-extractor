"""Derive checked PE32 C boundary shapes from pinned public headers.

Clang is used as a declaration and ABI-layout oracle.  Its output is not a
second execution IR: each selected declaration is immediately normalized into
the repository's canonical ``BoundarySchemaV1`` and ``TargetDataLayoutV1``
artifacts, which the ordinary IA-32 dialect checker lowers again when the
external environment is resolved.

The generated machine profile intentionally contains no memory, lifecycle, or
world-effect claims.  C pointer spelling cannot authorize those facts.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..errors import ToolkitInputError
from ..util import sha256_file, write_json
from .machine_import_profiles import STATIC_MACHINE_IMPORT_PROFILE_V2_FORMAT


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_LLVM_DECLARATION = re.compile(
    r"^declare\s+(?:[^@\n]*?\s)?(?P<result>void|ptr|i\d+|half|float|double|x86_fp80)\s+"
    r"@(?P<name>[A-Za-z_.$][A-Za-z0-9_.$]*)\((?P<arguments>.*)\)\s*(?:#\d+)?\s*$"
)
_LLVM_SIZE_GLOBAL = re.compile(
    r"^@spx_(?P<kind>argument|result)_(?P<function>\d+)"
    r"(?:_(?P<argument>\d+))?\s*=.*?global\s+"
    r"\[(?P<size>\d+)\s+x\s+i8\]"
)
_LLVM_ALIGN_GLOBAL = re.compile(
    r"^@spx_(?P<kind>argument|result)_alignment_(?P<function>\d+)"
    r"(?:_(?P<argument>\d+))?\s*=.*?global\s+"
    r"\[(?P<size>\d+)\s+x\s+i8\]"
)


@dataclass(frozen=True)
class HeaderFunctionDeclaration:
    name: str
    qualified_type: str
    parameter_types: tuple[str, ...]
    result_type: str
    variadic: bool


def build_header_machine_abi_profile(
    *,
    clang: Path,
    translation_source: Path,
    headers: Sequence[Path],
    includes: Sequence[str],
    include_directories: Sequence[Path],
    function_prefixes: Sequence[str],
    profile_id: str,
    provider_dll: str,
    out: Path,
) -> dict[str, Any]:
    """Run the pinned Clang probes and emit one canonical ABI profile.

    Keeping orchestration here lets Nix use the shared content-addressed JSON
    phase constructor.  Clang remains a declaration/layout oracle; the emitted
    artifact is still normalized through the repository boundary codecs.
    """

    clang = Path(clang)
    translation_source = Path(translation_source)
    header_paths = tuple(Path(path) for path in headers)
    include_paths = tuple(Path(path) for path in include_directories)
    if not clang.is_file():
        raise ToolkitInputError("header ABI extraction Clang executable is absent")
    if not translation_source.is_file():
        raise ToolkitInputError("header ABI extraction translation source is absent")
    if any(not path.is_file() for path in header_paths):
        raise ToolkitInputError("header ABI extraction input header is absent")
    clang_base = [
        str(clang),
        "--target=i686-w64-windows-gnu",
        "-fms-extensions",
        "-fdeclspec",
        "-Wno-everything",
        *(argument for path in include_paths for argument in ("-I", str(path))),
    ]
    with tempfile.TemporaryDirectory(prefix="spx-header-abi-") as temporary:
        root = Path(temporary)
        ast = root / "ast.json"
        probe = root / "probe.c"
        llvm = root / "probe.ll"
        with ast.open("wb") as stream:
            _run_clang(
                [
                    *clang_base,
                    "-Xclang",
                    "-ast-dump=json",
                    "-fsyntax-only",
                    str(translation_source),
                ],
                stdout=stream,
                context="AST declaration probe",
            )
        write_header_abi_probe_source(
            ast_json=ast,
            includes=includes,
            function_prefixes=function_prefixes,
            out=probe,
        )
        _run_clang(
            [
                *clang_base,
                "-O0",
                "-S",
                "-emit-llvm",
                "-o",
                str(llvm),
                str(probe),
            ],
            context="LLVM ABI-layout probe",
        )
        version = _run_clang(
            [str(clang), "--version"],
            capture_output=True,
            context="version probe",
        ).stdout.decode("utf-8", errors="strict").splitlines()[0]
        return extract_header_machine_abi_profile(
            ast_json=ast,
            llvm_ir=llvm,
            headers=header_paths,
            includes=includes,
            function_prefixes=function_prefixes,
            profile_id=profile_id,
            provider_dll=provider_dll,
            clang_version=version,
            out=Path(out),
        )


def _run_clang(
    arguments: Sequence[str],
    *,
    stdout: Any = None,
    capture_output: bool = False,
    context: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(arguments),
            check=True,
            stdout=subprocess.PIPE if capture_output else stdout,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        stderr = getattr(exc, "stderr", None)
        if isinstance(stderr, bytes) and stderr:
            detail = ": " + stderr.decode("utf-8", errors="replace").strip()
        raise ToolkitInputError(f"Clang header ABI {context} failed{detail}") from exc


def discover_header_function_declarations(
    ast_json: Path,
    *,
    function_prefixes: Sequence[str],
) -> tuple[HeaderFunctionDeclaration, ...]:
    """Select unimplemented external C declarations from one Clang AST."""

    prefixes = tuple(_prefix(value) for value in function_prefixes)
    if not prefixes:
        raise ToolkitInputError("header ABI extraction has no function prefixes")
    ast = _read_json(ast_json, "Clang AST")
    by_name: dict[str, HeaderFunctionDeclaration] = {}
    conflicts: set[str] = set()
    for row in _walk_ast(ast):
        if row.get("kind") != "FunctionDecl":
            continue
        name = row.get("name")
        if (
            not isinstance(name, str)
            or _IDENTIFIER.fullmatch(name) is None
            or not name.startswith(prefixes)
            or row.get("storageClass") == "static"
            or any(
                isinstance(child, Mapping) and child.get("kind") == "CompoundStmt"
                for child in row.get("inner", [])
                if isinstance(row.get("inner"), list)
            )
        ):
            continue
        type_row = row.get("type")
        qualified = (
            type_row.get("qualType") if isinstance(type_row, Mapping) else None
        )
        if not isinstance(qualified, str) or not qualified:
            conflicts.add(name)
            continue
        parameters = tuple(
            str(child.get("type", {}).get("qualType"))
            for child in row.get("inner", [])
            if isinstance(child, Mapping) and child.get("kind") == "ParmVarDecl"
        )
        if any(value in {"", "None"} for value in parameters):
            conflicts.add(name)
            continue
        result_type = _function_result_type(qualified)
        declaration = HeaderFunctionDeclaration(
            name=name,
            qualified_type=qualified,
            parameter_types=parameters,
            result_type=result_type,
            variadic=_function_is_variadic(qualified),
        )
        prior = by_name.get(name)
        if prior is None:
            by_name[name] = declaration
        elif prior != declaration:
            conflicts.add(name)
    if conflicts:
        raise ToolkitInputError(
            "header ABI declarations are missing or conflicting: "
            + ", ".join(sorted(conflicts))
        )
    if not by_name:
        raise ToolkitInputError("header ABI extraction selected no declarations")
    return tuple(by_name[name] for name in sorted(by_name))


def write_header_abi_probe_source(
    *,
    ast_json: Path,
    includes: Sequence[str],
    function_prefixes: Sequence[str],
    out: Path,
) -> tuple[HeaderFunctionDeclaration, ...]:
    """Write the small C probe whose LLVM declarations expose physical ABI."""

    declarations = discover_header_function_declarations(
        ast_json, function_prefixes=function_prefixes
    )
    lines = [f"#include <{_include(value)}>" for value in includes]
    lines.append("")
    for function_index, declaration in enumerate(declarations):
        lines.append(
            f"void *spx_reference_{function_index} = "
            f"(void *)&{declaration.name};"
        )
        for argument_index, parameter_type in enumerate(
            declaration.parameter_types
        ):
            lines.append(
                f"unsigned char spx_argument_{function_index}_{argument_index}"
                f"[sizeof({parameter_type})];"
            )
            lines.append(
                "unsigned char "
                f"spx_argument_alignment_{function_index}_{argument_index}"
                f"[_Alignof({parameter_type})];"
            )
        if declaration.result_type != "void":
            lines.append(
                f"unsigned char spx_result_{function_index}"
                f"[sizeof({declaration.result_type})];"
            )
            lines.append(
                f"unsigned char spx_result_alignment_{function_index}"
                f"[_Alignof({declaration.result_type})];"
            )
    Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return declarations


def extract_header_machine_abi_profile(
    *,
    ast_json: Path,
    llvm_ir: Path,
    headers: Sequence[Path],
    includes: Sequence[str],
    function_prefixes: Sequence[str],
    profile_id: str,
    provider_dll: str,
    clang_version: str,
    out: Path,
) -> dict[str, Any]:
    """Normalize pinned Clang ABI output into the existing V2 profile."""

    declarations = discover_header_function_declarations(
        ast_json, function_prefixes=function_prefixes
    )
    header_paths = tuple(Path(path).resolve() for path in headers)
    include_names = tuple(_include(value) for value in includes)
    if len(header_paths) != len(include_names) or len(set(include_names)) != len(
        include_names
    ):
        raise ToolkitInputError(
            "header ABI extraction requires one unique include per header"
        )
    profile = _identifier(profile_id, "header ABI profile ID")
    dll = _dll_name(provider_dll)
    try:
        llvm_text = Path(llvm_ir).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ToolkitInputError(f"cannot read Clang LLVM ABI output: {exc}") from exc
    sizes, alignments = _probe_layouts(llvm_text)
    llvm_declarations = _llvm_declarations(llvm_text)

    entries: list[dict[str, Any]] = []
    for function_index, declaration in enumerate(declarations):
        llvm = llvm_declarations.get(declaration.name)
        if llvm is None:
            raise ToolkitInputError(
                f"Clang LLVM ABI output omits declaration {declaration.name}"
            )
        llvm_result, llvm_arguments, llvm_variadic = llvm
        if llvm_variadic != declaration.variadic:
            raise ToolkitInputError(
                f"Clang AST and LLVM ABI disagree on variadic declaration "
                f"{declaration.name}"
            )
        parameter_sizes = tuple(
            _layout_value(
                sizes,
                ("argument", function_index, argument_index),
                f"{declaration.name} argument {argument_index} size",
            )
            for argument_index in range(len(declaration.parameter_types))
        )
        parameter_alignments = tuple(
            _layout_value(
                alignments,
                ("argument", function_index, argument_index),
                f"{declaration.name} argument {argument_index} alignment",
            )
            for argument_index in range(len(declaration.parameter_types))
        )
        result_size = (
            0
            if declaration.result_type == "void"
            else _layout_value(
                sizes,
                ("result", function_index, None),
                f"{declaration.name} result size",
            )
        )
        result_alignment = (
            1
            if declaration.result_type == "void"
            else _layout_value(
                alignments,
                ("result", function_index, None),
                f"{declaration.name} result alignment",
            )
        )
        canonical, argument_words, result_relations = _canonical_boundary(
            declaration=declaration,
            llvm_result=llvm_result,
            llvm_arguments=llvm_arguments,
            parameter_sizes=parameter_sizes,
            parameter_alignments=parameter_alignments,
            result_size=result_size,
            result_alignment=result_alignment,
        )
        arity = {
            "kind": "variadic" if declaration.variadic else "fixed",
            "minimum_words" if declaration.variadic else "words": argument_words,
        }
        entries.append({
            "id": f"header-abi:{dll}!{declaration.name}",
            "import": {"dll": dll, "symbol": declaration.name},
            "override": True,
            "abi_template": "pe32-cdecl-v1",
            "arity": arity,
            "disposition": "returns",
            "result_register_relations": result_relations,
            "canonical_boundary": canonical,
            "provenance": {
                "kind": "pinned_clang_header_abi_lowering",
                "declaration": declaration.qualified_type,
                "ast_sha256": sha256_file(ast_json),
                "llvm_ir_sha256": sha256_file(llvm_ir),
            },
        })

    result = {
        "format": STATIC_MACHINE_IMPORT_PROFILE_V2_FORMAT,
        "id": profile,
        "status": "complete",
        "provenance": {
            "kind": "pinned_clang_header_abi_catalog",
            "provider_dll": dll,
            "clang_version": str(clang_version).strip(),
            "ast_sha256": sha256_file(ast_json),
            "llvm_ir_sha256": sha256_file(llvm_ir),
            "headers": [
                {"include": include, "sha256": sha256_file(path)}
                for include, path in sorted(zip(include_names, header_paths))
            ],
            "function_prefixes": sorted(set(function_prefixes)),
        },
        "machine_import_signatures": entries,
        "counts": {
            "declarations": len(entries),
            "fixed": sum(entry["arity"]["kind"] == "fixed" for entry in entries),
            "variadic": sum(
                entry["arity"]["kind"] == "variadic" for entry in entries
            ),
        },
    }
    write_json(Path(out), result)
    return result


def _canonical_boundary(
    *,
    declaration: HeaderFunctionDeclaration,
    llvm_result: str,
    llvm_arguments: Sequence[str],
    parameter_sizes: Sequence[int],
    parameter_alignments: Sequence[int],
    result_size: int,
    result_alignment: int,
) -> tuple[dict[str, Any], int, list[dict[str, str]]]:
    sret_arguments = [argument for argument in llvm_arguments if " sret(" in argument]
    if len(sret_arguments) > 1:
        raise ToolkitInputError(f"{declaration.name} has multiple LLVM sret arguments")
    has_sret = bool(sret_arguments)
    physical_arguments = [
        argument for argument in llvm_arguments if " sret(" not in argument
    ]
    if len(physical_arguments) != len(parameter_sizes):
        raise ToolkitInputError(
            f"{declaration.name} LLVM argument inventory differs from its AST"
        )
    if has_sret and (llvm_result != "void" or result_size <= 0):
        raise ToolkitInputError(f"{declaration.name} has a contradictory sret ABI")

    types: list[dict[str, Any]] = [
        {"id": "unit", "kind": "void"},
        {"id": "u8", "kind": "integer", "width_bits": 8, "signed": False},
        {"id": "abi-opaque", "kind": "opaque", "nominal_id": "clang-abi-object"},
        {
            "id": "pointer",
            "kind": "pointer",
            "pointee_type_id": "abi-opaque",
            "qualifiers": [],
        },
    ]
    layouts: list[dict[str, Any]] = [
        _layout("u8", 1, 1, "integer"),
        _layout("pointer", 4, 4, "pointer"),
    ]
    cached: dict[tuple[Any, ...], str] = {
        ("void",): "unit",
        ("pointer",): "pointer",
    }

    def type_for(
        llvm_type: str,
        *,
        size: int,
        alignment: int,
        aggregate: bool,
        result: bool,
    ) -> str:
        key = (llvm_type, size, alignment, aggregate, result)
        prior = cached.get(key)
        if prior is not None:
            return prior
        identity = f"abi-type-{len(cached)}"
        if aggregate:
            types.append({
                "id": identity,
                "kind": "array",
                "element_type_id": "u8",
                "element_count": size,
            })
            layouts.append(
                _layout(
                    identity,
                    size,
                    alignment,
                    "aggregate-memory" if result else "aggregate-value",
                )
            )
        elif llvm_type in {"float", "double", "x86_fp80", "half"}:
            fmt, bits = {
                "half": ("binary16", 16),
                "float": ("binary32", 32),
                "double": ("binary64", 64),
                "x86_fp80": ("x87-extended80", 80),
            }[llvm_type]
            types.append({
                "id": identity,
                "kind": "float",
                "format": fmt,
                "value_bits": bits,
            })
            layouts.append(
                _layout(identity, size, alignment, "floating", value_bits=bits)
            )
        elif llvm_type == "ptr":
            return "pointer"
        else:
            matched = re.fullmatch(r"i(\d+)", llvm_type)
            if matched is None:
                raise ToolkitInputError(
                    f"{declaration.name} uses unsupported LLVM ABI type {llvm_type!r}"
                )
            bits = int(matched.group(1))
            types.append({
                "id": identity,
                "kind": "integer",
                "width_bits": bits,
                "signed": False,
            })
            layouts.append(
                _layout(identity, size, alignment, "integer", value_bits=bits)
            )
        cached[key] = identity
        return identity

    parameter_type_ids: list[str] = []
    parameters: list[dict[str, Any]] = []
    for index, (argument, size, alignment) in enumerate(
        zip(physical_arguments, parameter_sizes, parameter_alignments)
    ):
        llvm_type = _llvm_argument_type(argument)
        aggregate = " byval(" in argument
        type_id = type_for(
            llvm_type,
            size=size,
            alignment=alignment,
            aggregate=aggregate,
            result=False,
        )
        parameter_type_ids.append(type_id)
        parameters.append(_value(f"argument-{index}", type_id))

    if has_sret:
        result_type_id = type_for(
            "sret",
            size=result_size,
            alignment=result_alignment,
            aggregate=True,
            result=True,
        )
    elif llvm_result == "void":
        result_type_id = "unit"
    else:
        result_type_id = type_for(
            llvm_result,
            size=result_size,
            alignment=result_alignment,
            aggregate=False,
            result=True,
        )
    types.append({
        "id": "invoke-function",
        "kind": "function",
        "result_type_id": result_type_id,
        "parameter_type_ids": parameter_type_ids,
        "variadic": declaration.variadic,
        "calling_convention": "cdecl",
    })
    results = (
        [] if result_type_id == "unit" else [_value("result", result_type_id)]
    )
    schema = BoundarySchemaV1.create(
        schema_id=f"header-abi-{declaration.name}",
        types=types,
        signatures=[{
            "id": "invoke",
            "function_type_id": "invoke-function",
            "parameters": parameters,
            "results": results,
        }],
    )
    layout = TargetDataLayoutV1.create(
        target="i686-pc-windows-pe32",
        abi_dialect="pe32-i386-gnu-v1",
        byte_order="little",
        pointer_width_bits=32,
        packing="clang-target-layout",
        schema=schema,
        layouts=layouts,
    )
    argument_words = sum(max(4, ((size + 3) // 4) * 4) // 4 for size in parameter_sizes)
    if has_sret:
        argument_words += 1
    result_relations: list[dict[str, str]] = []
    if not has_sret and re.fullmatch(r"i(?:1|8|16|32)", llvm_result):
        result_relations = [{"register": "eax", "relation": "exact"}]
    elif not has_sret and llvm_result == "ptr":
        result_relations = [{"register": "eax", "relation": "exact"}]
    elif not has_sret and llvm_result == "i64":
        result_relations = [
            {"register": "eax", "relation": "exact"},
            {"register": "edx", "relation": "exact"},
        ]
    return ({
        "boundary_schema": schema.to_payload(),
        "target_data_layout": layout.to_payload(),
        "signature_id": "invoke",
    }, argument_words, result_relations)


def _probe_layouts(
    llvm_text: str,
) -> tuple[dict[tuple[str, int, int | None], int], dict[tuple[str, int, int | None], int]]:
    sizes: dict[tuple[str, int, int | None], int] = {}
    alignments: dict[tuple[str, int, int | None], int] = {}
    for line in llvm_text.splitlines():
        for pattern, destination in (
            (_LLVM_SIZE_GLOBAL, sizes),
            (_LLVM_ALIGN_GLOBAL, alignments),
        ):
            matched = pattern.match(line)
            if matched is None:
                continue
            key = (
                matched.group("kind"),
                int(matched.group("function")),
                (
                    None
                    if matched.group("argument") is None
                    else int(matched.group("argument"))
                ),
            )
            value = int(matched.group("size"))
            if key in destination and destination[key] != value:
                raise ToolkitInputError("Clang ABI probe repeats a conflicting layout")
            destination[key] = value
    return sizes, alignments


def _llvm_declarations(
    llvm_text: str,
) -> dict[str, tuple[str, tuple[str, ...], bool]]:
    result: dict[str, tuple[str, tuple[str, ...], bool]] = {}
    for line in llvm_text.splitlines():
        matched = _LLVM_DECLARATION.match(line)
        if matched is None:
            continue
        name = matched.group("name")
        arguments = _split_llvm_arguments(matched.group("arguments"))
        variadic = bool(arguments and arguments[-1] == "...")
        if variadic:
            arguments = arguments[:-1]
        row = (matched.group("result"), tuple(arguments), variadic)
        prior = result.get(name)
        if prior is not None and prior != row:
            raise ToolkitInputError(f"LLVM ABI repeats conflicting declaration {name}")
        result[name] = row
    return result


def _split_llvm_arguments(value: str) -> list[str]:
    if not value.strip():
        return []
    result: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(value):
        if character in "([{<":
            depth += 1
        elif character in ")]}>":
            depth -= 1
        elif character == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return result


def _llvm_argument_type(value: str) -> str:
    matched = re.match(r"(void|ptr|i\d+|half|float|double|x86_fp80)(?:\s|$)", value)
    if matched is None:
        raise ToolkitInputError(f"unsupported LLVM ABI argument {value!r}")
    return matched.group(1)


def _function_result_type(qualified: str) -> str:
    # The outer parameter list is the first parenthesis for ordinary C
    # functions.  Clang may omit whitespace for pointer returns.  A function
    # returning another function pointer necessarily puts a parenthesis in the
    # declarator prefix and is deliberately rejected instead of guessed.
    marker = qualified.find("(")
    if marker < 0:
        raise ToolkitInputError(
            f"unsupported Clang function type spelling {qualified!r}"
        )
    result = qualified[:marker].strip()
    if not result or "(" in result or ")" in result:
        raise ToolkitInputError(
            f"callback-returning function type requires an explicit boundary: {qualified!r}"
        )
    return result


def _function_is_variadic(qualified: str) -> bool:
    return bool(re.search(r"(?:^|,)\s*\.\.\.\s*\)", qualified))


def _layout(
    type_id: str,
    size_bytes: int,
    alignment_bytes: int,
    abi_class: str,
    *,
    value_bits: int | None = None,
) -> dict[str, Any]:
    if size_bytes <= 0 or alignment_bytes <= 0:
        raise ToolkitInputError("Clang ABI layout has a non-positive size or alignment")
    storage_bits = size_bytes * 8
    useful_bits = storage_bits if value_bits is None else value_bits
    return {
        "type_id": type_id,
        "size_bits": storage_bits,
        "alignment_bits": alignment_bytes * 8,
        "value_bits": useful_bits,
        "abi_class": abi_class,
        "fields": [],
        "padding": (
            []
            if useful_bits == storage_bits
            else [{"offset_bits": useful_bits, "width_bits": storage_bits - useful_bits}]
        ),
    }


def _value(identity: str, type_id: str) -> dict[str, Any]:
    return {
        "id": identity,
        "type_id": type_id,
        "interpretation": "value",
        "nullable": False,
        "access": "none",
        "extent": {"kind": "none", "bytes": None, "value_id": None},
        "resource_kind": None,
        "provider_domain": None,
    }


def _layout_value(
    values: Mapping[tuple[str, int, int | None], int],
    key: tuple[str, int, int | None],
    context: str,
) -> int:
    value = values.get(key)
    if value is None or value <= 0:
        raise ToolkitInputError(f"Clang ABI probe omits {context}")
    return value


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


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be a JSON object")
    return value


def _prefix(value: object) -> str:
    if not isinstance(value, str) or not value or _IDENTIFIER.fullmatch(value) is None:
        raise ToolkitInputError("header ABI function prefix must be a C identifier")
    return value


def _include(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(("/", "."))
        or ".." in Path(value).parts
        or any(character in value for character in '<>"\n\r')
    ):
        raise ToolkitInputError("header ABI include name is invalid")
    return value


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or re.fullmatch(r"[A-Za-z0-9._:-]+", value) is None:
        raise ToolkitInputError(f"{context} is invalid")
    return value


def _dll_name(value: object) -> str:
    if not isinstance(value, str) or not value or not value.lower().endswith(".dll"):
        raise ToolkitInputError("header ABI provider DLL name is invalid")
    return value.lower()


__all__ = [
    "HeaderFunctionDeclaration",
    "discover_header_function_declarations",
    "extract_header_machine_abi_profile",
    "write_header_abi_probe_source",
]
