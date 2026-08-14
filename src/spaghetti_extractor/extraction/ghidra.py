"""Optional Ghidra frontend for untrusted static extraction proposals."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json


GHIDRA_PROPOSAL_FORMAT = "spaghetti-extractor-ghidra-proposal-v1"
GHIDRA_SCRIPT = "SpaghettiExtractorStaticProposal.java"
PYTHON_RESOURCES = ("src/spaghetti_extractor/resources/ghidra",)


def _resolve_analyze_headless(value: str | None) -> str:
    if value:
        return value
    configured = os.environ.get("SPAGHETTI_EXTRACTOR_GHIDRA_HEADLESS")
    if configured:
        return configured
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    for variable in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        root = os.environ.get(variable)
        if root:
            candidate = Path(root) / "support" / "analyzeHeadless"
            if candidate.is_file():
                return str(candidate)
    return "analyzeHeadless"


def _resolve_script_path(value: Path | None) -> Path:
    candidates = [Path(__file__).resolve().parents[1] / "resources" / "ghidra"]
    if value is not None:
        candidates.insert(0, Path(value))
    for candidate in candidates:
        if candidate.is_dir() and (candidate / GHIDRA_SCRIPT).is_file():
            return candidate.resolve()
    rendered = ", ".join(str(candidate) for candidate in candidates)
    raise StageAInputError(
        f"Ghidra proposal script {GHIDRA_SCRIPT} was not found; searched: {rendered}"
    )


def _artifact(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": sha256_file(path)}


def _validate_export(path: Path, *, binary_sha256: str) -> str | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return f"Ghidra output is not readable JSON: {exc}"
    if not isinstance(value, dict):
        return "Ghidra output must be a JSON object"
    if value.get("schema_version") != 1:
        return "Ghidra output has an unsupported schema version"
    if value.get("binary_sha256") != binary_sha256:
        return "Ghidra output is bound to a different binary"
    for field in (
        "functions",
        "basic_blocks",
        "cfg_edges",
        "call_edges",
        "data_refs",
        "globals",
    ):
        if not isinstance(value.get(field), list):
            return f"Ghidra output field {field!r} must be an array"
    return None


def export_ghidra_proposal(
    *,
    binary: Path,
    out: Path,
    analyze_headless: str | None = None,
    script_path: Path | None = None,
    project_dir: Path | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Run Ghidra statically and bind its non-authorizing output to exact bytes."""

    binary = Path(binary)
    if not binary.is_file():
        raise StageAInputError(f"Ghidra proposal input is not available: {binary}")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    binary_sha256 = sha256_file(binary)
    scripts = _resolve_script_path(script_path)
    projects = Path(project_dir) if project_dir is not None else out / "projects"
    projects.mkdir(parents=True, exist_ok=True)
    proposal = out / "proposal.json"
    command = [
        _resolve_analyze_headless(analyze_headless),
        str(projects),
        f"spaghetti-proposal-{binary_sha256[:16]}",
        "-import",
        str(binary),
        "-scriptPath",
        str(scripts),
        "-postScript",
        GHIDRA_SCRIPT,
        str(proposal),
        binary_sha256,
        "-deleteProject",
    ]
    issue: str | None = None
    returncode: int | None = None
    stdout = ""
    stderr = ""
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
        if completed.returncode != 0:
            issue = f"Ghidra exited with status {completed.returncode}"
        elif not proposal.is_file():
            issue = "Ghidra completed without producing the proposal"
        else:
            issue = _validate_export(proposal, binary_sha256=binary_sha256)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        issue = "Ghidra proposal extraction timed out"
    except OSError as exc:
        issue = f"Ghidra could not be executed: {exc}"

    (out / "stdout.txt").write_text(stdout, encoding="utf-8")
    (out / "stderr.txt").write_text(stderr, encoding="utf-8")
    report: dict[str, Any] = {
        "format": GHIDRA_PROPOSAL_FORMAT,
        "status": "complete" if issue is None else "incomplete",
        "authority": "untrusted-proposal",
        "executes_original_binary": False,
        "binary": _artifact(binary),
        "command": command,
        "returncode": returncode,
        "proposal": _artifact(proposal) if proposal.is_file() else None,
        "issues": [] if issue is None else [{"code": "ghidra_proposal_incomplete", "detail": issue}],
    }
    write_json(out / "report.json", report)
    return report


__all__ = ["GHIDRA_PROPOSAL_FORMAT", "export_ghidra_proposal"]
