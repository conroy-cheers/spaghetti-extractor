from __future__ import annotations

import json
import re
import shlex
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .db import connect, initialize
from .labels import ensure_label, static_cross_check_label
from .util import json_dumps, utc_now


DEFAULT_STATIC_CROSS_CHECK_TOOLS = ("llvm-readobj", "rizin")


@dataclass(frozen=True)
class ToolSection:
    name: str
    rva: int
    raw_size: int | None
    virtual_size: int | None
    executable: bool


def run_static_cross_checks(
    db_path: Path,
    *,
    tools: Iterable[str] = DEFAULT_STATIC_CROSS_CHECK_TOOLS,
    scopes: Iterable[str] = ("included", "candidate"),
    filenames: Iterable[str] | None = None,
    timeout_seconds: int | None = 30,
) -> dict[str, Any]:
    conn = connect(db_path)
    initialize(conn)
    rows = _select_binaries(conn, scopes=scopes, filenames=filenames)
    if not rows:
        raise ValueError("no cataloged binaries matched the requested scope/filename filters")

    requested_tools = tuple(tools)
    result = {
        "selected_binaries": len(rows),
        "tools": list(requested_tools),
        "checks": 0,
        "passed": 0,
        "failed": 0,
        "failures": [],
    }

    with conn:
        for binary in rows:
            binary_path = Path(binary["source_root"]) / str(binary["path"])
            catalog_sections = _catalog_sections(conn, int(binary["id"]))
            for tool in requested_tools:
                check = _run_tool_check(
                    tool,
                    binary_path,
                    image_base=int(binary["image_base"] or 0),
                    catalog_sections=catalog_sections,
                    timeout_seconds=timeout_seconds,
                )
                label = _record_check(conn, binary, check)
                result["checks"] += 1
                if check["status"] == "pass":
                    result["passed"] += 1
                else:
                    result["failed"] += 1
                    result["failures"].append(
                        {
                            "label": label,
                            "binary": binary["path"],
                            "tool": tool,
                            "status": check["status"],
                            "summary": check["evidence"].get("summary", ""),
                        }
                    )
    conn.close()
    return result


def _run_tool_check(
    tool: str,
    binary_path: Path,
    *,
    image_base: int,
    catalog_sections: list[dict[str, Any]],
    timeout_seconds: int | None,
) -> dict[str, Any]:
    if tool == "llvm-readobj":
        command = [tool, "--sections", str(binary_path)]
        parser = parse_llvm_readobj_sections
        strict_virtual_size = True
    elif tool in {"rizin", "r2", "radare2"}:
        executable = "r2" if tool == "radare2" else tool
        command = [executable, "-q", "-c", "iSj", "-c", "q", str(binary_path)]
        parser = lambda stdout: parse_rizin_sections(stdout, image_base=image_base)
        strict_virtual_size = False
    else:
        raise ValueError(f"unknown static cross-check tool: {tool}")

    try:
        proc = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        return {
            "tool": tool,
            "command": command,
            "status": "error",
            "section_count": 0,
            "executable_section_count": 0,
            "evidence": {"summary": f"tool not found: {exc.filename or tool}", "missing": [], "mismatches": []},
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "tool": tool,
            "command": command,
            "status": "error",
            "section_count": 0,
            "executable_section_count": 0,
            "evidence": {
                "summary": f"tool timed out after {timeout_seconds} seconds",
                "stdout": _bounded_text(exc.stdout or ""),
                "stderr": _bounded_text(exc.stderr or ""),
                "missing": [],
                "mismatches": [],
            },
        }

    if proc.returncode != 0:
        return {
            "tool": tool,
            "command": command,
            "status": "error",
            "section_count": 0,
            "executable_section_count": 0,
            "evidence": {
                "summary": f"tool exited with {proc.returncode}",
                "stdout": _bounded_text(proc.stdout),
                "stderr": _bounded_text(proc.stderr),
                "missing": [],
                "mismatches": [],
            },
        }

    try:
        observed = parser(proc.stdout)
    except Exception as exc:
        return {
            "tool": tool,
            "command": command,
            "status": "error",
            "section_count": 0,
            "executable_section_count": 0,
            "evidence": {
                "summary": f"could not parse {tool} section output: {exc}",
                "stdout": _bounded_text(proc.stdout),
                "missing": [],
                "mismatches": [],
            },
        }

    evidence = compare_sections(catalog_sections, observed, strict_virtual_size=strict_virtual_size)
    status = "pass" if not evidence["missing"] and not evidence["extra"] and not evidence["mismatches"] else "fail"
    evidence["summary"] = (
        f"{tool} executable section cross-check passed"
        if status == "pass"
        else f"{tool} executable section cross-check found disagreement"
    )
    return {
        "tool": tool,
        "command": command,
        "status": status,
        "section_count": len(observed),
        "executable_section_count": sum(1 for section in observed if section.executable),
        "evidence": evidence,
    }


def parse_llvm_readobj_sections(stdout: str) -> list[ToolSection]:
    sections: list[ToolSection] = []
    current: dict[str, Any] | None = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped == "Section {":
            current = {"executable": False}
            continue
        if current is None:
            continue
        if stripped == "}":
            if "name" in current and "rva" in current:
                sections.append(
                    ToolSection(
                        name=str(current["name"]),
                        rva=int(current["rva"]),
                        raw_size=current.get("raw_size"),
                        virtual_size=current.get("virtual_size"),
                        executable=bool(current["executable"]),
                    )
                )
            current = None
            continue
        if stripped.startswith("Name:"):
            current["name"] = stripped.split(":", 1)[1].strip().split(" ", 1)[0]
        elif stripped.startswith("VirtualAddress:"):
            current["rva"] = _parse_int(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("VirtualSize:"):
            current["virtual_size"] = _parse_int(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("RawDataSize:"):
            current["raw_size"] = _parse_int(stripped.split(":", 1)[1].strip())
        elif "IMAGE_SCN_MEM_EXECUTE" in stripped:
            current["executable"] = True
    return sections


def parse_rizin_sections(stdout: str, *, image_base: int) -> list[ToolSection]:
    payload = json.loads(stdout)
    sections: list[ToolSection] = []
    for item in payload:
        vaddr = int(item.get("vaddr", 0))
        rva = vaddr - image_base if image_base and vaddr >= image_base else vaddr
        sections.append(
            ToolSection(
                name=str(item.get("name", "")),
                rva=rva,
                raw_size=int(item["size"]) if item.get("size") is not None else None,
                virtual_size=None,
                executable="x" in str(item.get("perm", "")),
            )
        )
    return sections


def compare_sections(
    catalog_sections: list[dict[str, Any]],
    observed_sections: list[ToolSection],
    *,
    strict_virtual_size: bool,
) -> dict[str, Any]:
    observed_by_key = {_section_key(section.name, section.rva): section for section in observed_sections}
    catalog_by_key = {
        _section_key(str(section["name"]), int(section["virtual_address"])): section for section in catalog_sections
    }
    observed_by_rva = {int(section.rva): section for section in observed_sections}
    missing = []
    extra = []
    mismatches = []
    matched_observed_keys: set[tuple[str, int]] = set()

    for key, expected in catalog_by_key.items():
        observed = observed_by_key.get(key)
        if observed is None and _allows_rva_only_section_match(str(expected["name"])):
            observed = observed_by_rva.get(int(expected["virtual_address"]))
            if observed is not None and not _allows_rva_only_section_match(observed.name):
                observed = None
        display_name = _section_display_name(str(expected["name"]), int(expected["virtual_address"]))
        if observed is None:
            missing.append({"section": display_name})
            continue
        matched_observed_keys.add(_section_key(observed.name, observed.rva))
        expected_fields = {
            "rva": int(expected["virtual_address"]),
            "raw_size": int(expected["raw_size"]),
            "executable": bool(expected["executable"]),
        }
        observed_fields = {
            "rva": observed.rva,
            "raw_size": observed.raw_size,
            "executable": observed.executable,
        }
        if strict_virtual_size:
            expected_fields["virtual_size"] = int(expected["virtual_size"])
            observed_fields["virtual_size"] = observed.virtual_size
        differences = {
            key: {"catalog": expected_fields[key], "tool": observed_fields[key]}
            for key in expected_fields
            if expected_fields[key] != observed_fields.get(key)
        }
        if differences:
            mismatches.append({"section": display_name, "fields": differences})

    for key, observed in observed_by_key.items():
        if key not in catalog_by_key and key not in matched_observed_keys:
            extra.append({"section": _section_display_name(observed.name, observed.rva)})

    return {
        "catalog_sections": len(catalog_sections),
        "tool_sections": len(observed_sections),
        "catalog_executable_sections": sum(1 for section in catalog_sections if section["executable"]),
        "tool_executable_sections": sum(1 for section in observed_sections if section.executable),
        "missing": missing,
        "extra": extra,
        "mismatches": mismatches,
    }


def _section_key(name: str, rva: int) -> tuple[str, int]:
    return (_normalize_section_name(name), int(rva))


def _normalize_section_name(name: str) -> str:
    stripped = name.strip()
    # Some COFF/PE tools resolve long section names from the string table while
    # pefile preserves the raw slash-offset name. The executable section
    # identity is still anchored by RVA, so normalize known equivalents here.
    if stripped == "/4":
        return ".eh_frame"
    duplicate = re.match(r"^(?P<base>.+)_0x[0-9A-Fa-f]+$", stripped)
    if duplicate:
        return duplicate.group("base")
    return stripped


def _section_display_name(name: str, rva: int) -> str:
    normalized = _normalize_section_name(name)
    return f"{normalized}@0x{int(rva):x}"


def _allows_rva_only_section_match(name: str) -> bool:
    normalized = _normalize_section_name(name)
    return normalized in {"", ".eh_frame"}


def _record_check(conn: sqlite3.Connection, binary: sqlite3.Row, check: dict[str, Any]) -> str:
    checked_at = utc_now()
    attempt = (
        int(
            conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM static_cross_checks
                WHERE binary_id = ? AND tool = ?
                """,
                (int(binary["id"]), str(check["tool"])),
            ).fetchone()["count"]
        )
        + 1
    )
    label = static_cross_check_label(str(binary["label"]), str(check["tool"]), checked_at, attempt)
    evidence = check["evidence"]
    ensure_label(
        conn,
        label,
        "static_cross_check",
        f"{binary['label']}:{check['tool']}",
        str(evidence.get("summary", "")),
        created_at=checked_at,
    )
    conn.execute(
        """
        INSERT INTO static_cross_checks(
          label, binary_id, tool, status, checked_at, command,
          section_count, executable_section_count, evidence_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            label,
            int(binary["id"]),
            str(check["tool"]),
            str(check["status"]),
            checked_at,
            shlex.join(str(part) for part in check["command"]),
            int(check["section_count"]),
            int(check["executable_section_count"]),
            json_dumps(evidence),
        ),
    )
    return label


def _select_binaries(
    conn: sqlite3.Connection,
    *,
    scopes: Iterable[str],
    filenames: Iterable[str] | None,
) -> list[sqlite3.Row]:
    scope_values = [str(scope) for scope in scopes]
    if not scope_values:
        raise ValueError("at least one scope is required")
    filename_values = [filename.lower() for filename in filenames or []]
    params: list[Any] = scope_values
    where = [f"scope IN ({', '.join('?' for _ in scope_values)})"]
    if filename_values:
        where.append(f"lower(filename) IN ({', '.join('?' for _ in filename_values)})")
        params.extend(filename_values)
    return conn.execute(
        f"""
        SELECT id, label, path, filename, sha256, image_base, source_root, scope
        FROM binaries
        WHERE {' AND '.join(where)}
        ORDER BY scope, path, sha256
        """,
        params,
    ).fetchall()


def _catalog_sections(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    return [
        {
            **dict(row),
            "executable": "execute" in re.split(r"[\s,]+", str(row["flags"])),
        }
        for row in conn.execute(
            """
            SELECT name, virtual_address, virtual_size, raw_size, flags
            FROM sections
            WHERE binary_id = ?
            ORDER BY virtual_address, name
            """,
            (binary_id,),
        )
    ]


def _parse_int(value: str) -> int:
    cleaned = re.sub(r"\s.*$", "", value.strip())
    return int(cleaned, 16) if cleaned.lower().startswith("0x") else int(cleaned)


def _bounded_text(value: str | bytes, limit: int = 8000) -> str:
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n... truncated ...\n" + text[-half:]
