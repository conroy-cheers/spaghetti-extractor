"""Restricted-C profile checks for statically refined portable components."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .source import load_component_source_package


PROFILE_ID = "portable-component-c11-cbmc-v1"
_FORBIDDEN = {
    "inline_assembly": re.compile(r"\b(?:asm|__asm|__asm__)\b"),
    "volatile_storage": re.compile(r"\bvolatile\b"),
    "atomic_storage": re.compile(r"\b(?:_Atomic|atomic_[A-Za-z0-9_]*)\b"),
    "nonlocal_control": re.compile(r"\b(?:setjmp|longjmp|sigsetjmp|siglongjmp)\s*\("),
    "thread_creation": re.compile(r"\b(?:CreateThread|_beginthreadex|pthread_create)\s*\("),
    "unrestricted_allocation": re.compile(r"\b(?:malloc|calloc|realloc|free)\s*\("),
    "cbmc_intrinsic": re.compile(r"\b__CPROVER_[A-Za-z0-9_]*\b"),
    "conditional_compilation": re.compile(
        r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b"
    ),
    "thread_local_storage": re.compile(r"\b(?:_Thread_local|thread_local)\b"),
}


def check_component_source_profile(*, package: Path | str) -> dict[str, object]:
    source = load_component_source_package(package)
    root = Path(package)
    if root.is_file():
        root = root.parent
    issues: list[dict[str, object]] = []
    for row in source["files"]:
        if not isinstance(row, Mapping) or not str(row.get("path", "")).endswith((".c", ".h")):
            continue
        relative = str(row["path"])
        path = root / "sources" / relative
        text = path.read_text(encoding="utf-8")
        if relative.endswith('.h'):
            text = _ordinary_header_guard(text)
        lexical = _strip_comments_and_literals(text)
        for code, pattern in _FORBIDDEN.items():
            match = pattern.search(lexical)
            if match is None:
                continue
            issues.append({
                "status": "incomplete",
                "code": f"restricted_c_{code}",
                "source": {"path": relative, "line": lexical.count("\n", 0, match.start()) + 1},
            })
        if relative.endswith((".c", ".h")):
            for offset in _top_level_object_declarations(lexical):
                issues.append({
                    "status": "incomplete",
                    "code": "restricted_c_hidden_storage",
                    "source": {
                        "path": relative,
                        "line": lexical.count("\n", 0, offset) + 1,
                    },
                })
            for offset in _block_scope_static_storage(lexical):
                issues.append({
                    "status": "incomplete",
                    "code": "restricted_c_hidden_static_storage",
                    "source": {
                        "path": relative,
                        "line": lexical.count("\n", 0, offset) + 1,
                    },
                })
        for offset in _nonconstant_macro_definitions(text):
            issues.append({
                "status": "incomplete",
                "code": "restricted_c_macro_definition",
                "source": {
                    "path": relative,
                    "line": text.count("\n", 0, offset) + 1,
                },
            })
    status = "incomplete" if issues else "satisfied"
    core: dict[str, object] = {
        "status": status,
        "profile_id": PROFILE_ID,
        "component_id": source["lift_unit_id"],
        "bindings": {"implementation_sha256": source["implementation_sha256"]},
        "issues": sorted(issues, key=lambda row: (str(row["code"]), str(row["source"]))),
        "policy": {
            "compiler_semantics_assumed_correct": True,
            "raw_machine_addresses_forbidden": True,
            "undeclared_mutable_globals_forbidden": True,
            "operator_behavior_examples_used": False,
        },
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _strip_comments_and_literals(text: str) -> str:
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    return pattern.sub(lambda match: "\n" * match.group(0).count("\n"), text)


def _ordinary_header_guard(text: str) -> str:
    """Ignore only an outer conventional guard; inspect every enclosed token.

    Nested conditionals and executable macros remain subject to the profile.
    Guard recognition changes scanning, never the bytes compiled or bound.
    """
    lexical=_strip_comments_and_literals(text).splitlines()
    occupied=[i for i,line in enumerate(lexical) if line.strip()]
    if len(occupied)<3:return text
    first,second,last=occupied[0],occupied[1],occupied[-1]
    match=re.fullmatch(r'\s*#\s*ifndef\s+([A-Za-z_][A-Za-z0-9_]*)\s*',lexical[first])
    # Reserved/compiler macros are configuration tests, not hygienic guards.
    # In particular, hiding __CPROVER__ here would exempt a host/proof conditional
    # from both the conditional-compilation and intrinsic restrictions below.
    if (match is None or match[1].startswith('_') or match[1] in {'WIN32','WIN64','linux','unix'}
            or re.fullmatch(r'\s*#\s*define\s+'+re.escape(match[1])+r'\s*',lexical[second]) is None
            or re.fullmatch(r'\s*#\s*endif\s*',lexical[last]) is None):return text
    lines=text.splitlines(keepends=True)
    for i,pattern in [(first,r'#\s*ifndef\s+'+re.escape(match[1])),
                      (second,r'#\s*define\s+'+re.escape(match[1])),(last,r'#\s*endif\b')]:
        lines[i]=re.sub(pattern,lambda m:' '*len(m[0]),lines[i],count=1)
    return ''.join(lines)


def _top_level_object_declarations(text: str) -> list[int]:
    """Locate file-scope C object declarations in the restricted profile.

    The source language deliberately permits helper functions, prototypes,
    enums, structs, and typedefs, but all mutable state must live in the typed
    operation context.  This small scanner is sufficient because comments and
    literals have already been erased and preprocessor conditionals are
    rejected separately.
    """

    clean = re.sub(r"(?m)^\s*#.*$", "", text)
    result: list[int] = []
    brace_depth = 0
    statement_start = 0
    function_braces: list[bool] = []
    for index, character in enumerate(clean):
        if character == "{":
            prefix = clean[statement_start:index].strip()
            is_function = brace_depth == 0 and ")" in prefix and "=" not in prefix
            function_braces.append(is_function)
            brace_depth += 1
            continue
        if character == "}":
            if brace_depth == 0:
                continue
            brace_depth -= 1
            is_function = function_braces.pop()
            if brace_depth == 0 and is_function:
                statement_start = index + 1
            continue
        if character != ";" or brace_depth != 0:
            continue
        statement = clean[statement_start : index + 1]
        offset = statement_start + len(statement) - len(statement.lstrip())
        statement_start = index + 1
        normalized = statement.strip()
        if not normalized or normalized.startswith("typedef "):
            continue
        if normalized.startswith("_Static_assert"):
            continue
        if re.fullmatch(r"(?:struct|union|enum)\b[\s\S]*}\s*;", normalized):
            continue
        if re.fullmatch(r"(?:struct|union|enum)\s+[A-Za-z_][A-Za-z_0-9]*\s*;", normalized):
            continue
        if "=" not in normalized and "(*" not in normalized and "(" in normalized:
            continue
        result.append(offset)
    return result


def _block_scope_static_storage(text: str) -> list[int]:
    result: list[int] = []
    depth = 0
    for match in re.finditer(r"[{}]|\bstatic\b", text):
        token = match.group(0)
        if token == "{":
            depth += 1
        elif token == "}":
            depth = max(0, depth - 1)
        elif depth > 0:
            result.append(match.start())
    return result


def _nonconstant_macro_definitions(text: str) -> list[int]:
    allowed = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*\s+"
        r"(?:(?:U?INT(?:8|16|32|64)_C)\("
        r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)\)|"
        r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]*)\s*\Z"
    )
    result: list[int] = []
    for match in re.finditer(r"(?m)^\s*#\s*define\s+([^\n]+)$", text):
        if allowed.fullmatch(match.group(1).strip()) is None:
            result.append(match.start())
    return result


__all__ = ["PROFILE_ID", "check_component_source_profile"]
