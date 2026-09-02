"""Restricted-C profile checks for statically refined portable components."""

from __future__ import annotations

import json
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


__all__ = ["PROFILE_ID", "check_component_source_profile"]
