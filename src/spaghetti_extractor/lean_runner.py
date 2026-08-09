"""Small Lean module-graph compiler used by ISA qualification tests.

Accepted repository artifacts are built by Nix.  This runner exists for the
concrete ISA workers and focused tests; it compiles each imported module once
and never qualifies a reconstructed candidate.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from threading import Event
from typing import Any

from .stage_binary import StageAInputError


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_UNCHECKED = re.compile(r"\b(?:sorry|axiom|unsafe)\b")


def _output_current(source: Path, output: Path, dependencies: list[Path]) -> bool:
    try:
        stamp = output.stat().st_mtime_ns
        return stamp >= source.stat().st_mtime_ns and all(
            stamp >= dependency.stat().st_mtime_ns for dependency in dependencies
        )
    except OSError:
        return False


def run_lean_module_graph(
    lean_dir: Path,
    *,
    bundle: str,
    cancel_event: Event | None = None,
    command_timeout_seconds: float = 300,
    emit_c: bool = False,
) -> dict[str, Any]:
    """Compile one closed ``StageA`` import graph in dependency order."""

    if command_timeout_seconds <= 0:
        raise StageAInputError("Lean command timeout must be positive")
    started = time.monotonic()
    lean = shutil.which("lean")
    if lean is None:
        return {
            "status": "unavailable",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0.0,
        }

    stage_a = Path(lean_dir) / "StageA"
    imports: dict[str, list[str]] = {}
    order: list[str] = []
    active: set[str] = set()
    visited: set[str] = set()

    def visit(module: str) -> None:
        if module in visited:
            return
        if module in active:
            raise StageAInputError(f"cyclic Lean import involving StageA.{module}")
        source = stage_a / f"{module}.lean"
        if not source.is_file():
            raise StageAInputError(f"missing Lean module StageA.{module}")
        text = source.read_text(encoding="utf-8")
        if _UNCHECKED.search(text):
            raise StageAInputError(f"unchecked Lean marker in StageA.{module}")
        active.add(module)
        dependencies = list(dict.fromkeys(_IMPORT.findall(text)))
        imports[module] = dependencies
        for dependency in dependencies:
            visit(dependency)
        active.remove(module)
        visited.add(module)
        order.append(module)

    try:
        visit(bundle)
    except StageAInputError as exc:
        return {
            "status": "failed",
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    commands: list[list[str]] = []
    stdout: list[str] = []
    stderr: list[str] = []
    for module in order:
        if cancel_event is not None and cancel_event.is_set():
            return {
                "status": "cancelled",
                "returncode": None,
                "command": commands,
                "stdout": "".join(stdout),
                "stderr": "".join(stderr),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        source = stage_a / f"{module}.lean"
        output = stage_a / f"{module}.olean"
        c_output = stage_a / f"{module}.c"
        dependency_outputs = [stage_a / f"{name}.olean" for name in imports[module]]
        if _output_current(source, output, dependency_outputs) and (
            not emit_c or _output_current(source, c_output, dependency_outputs)
        ):
            continue
        command = [
            lean,
            "--trust=0",
            "-o",
            f"StageA/{module}.olean",
        ]
        if emit_c:
            command.extend(["-c", f"StageA/{module}.c"])
        command.append(f"StageA/{module}.lean")
        commands.append(command)
        try:
            completed = subprocess.run(
                command,
                cwd=lean_dir,
                env={**os.environ, "LEAN_PATH": "."},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=command_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "timeout",
                "returncode": None,
                "command": commands,
                "stdout": "".join(stdout) + (exc.stdout or ""),
                "stderr": "".join(stderr) + (exc.stderr or ""),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        stdout.append(completed.stdout)
        stderr.append(completed.stderr)
        if completed.returncode != 0:
            return {
                "status": "failed",
                "returncode": completed.returncode,
                "command": commands,
                "stdout": "".join(stdout),
                "stderr": "".join(stderr),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    return {
        "status": "checked",
        "returncode": 0,
        "command": commands,
        "stdout": "".join(stdout),
        "stderr": "".join(stderr),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


# Kept private to the package so existing ISA workers need no duplicate runner.
_run_lean = run_lean_module_graph
