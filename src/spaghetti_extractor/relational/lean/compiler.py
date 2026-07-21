from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from functools import lru_cache
from pathlib import Path
from threading import Event
from typing import Any

from ...stage_binary import StageAInputError
from ...util import sha256_bytes, sha256_file
from ..schema import RELATIONAL_APPROVED_AXIOMS


@lru_cache(maxsize=1)
def _lean_toolchain_identity() -> str:
    try:
        completed = subprocess.run(
            ["lean", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageAInputError("unable to identify the Lean toolchain") from exc
    identity = completed.stdout.strip()
    if not identity:
        raise StageAInputError("Lean toolchain identity is empty")
    return identity


def _lean_memory_arguments() -> list[str]:
    configured = os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB")
    if configured is None:
        return []
    try:
        memory_mb = int(configured)
    except ValueError as exc:
        raise StageAInputError(
            "SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB must be an integer"
        ) from exc
    if memory_mb <= 0:
        raise StageAInputError(
            "SPAGHETTI_EXTRACTOR_STAGE_A_LEAN_MEMORY_MB must be positive"
        )
    return ["-M", str(memory_mb)]


def _relational_cache_dir() -> Path | None:
    configured = os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE")
    if configured == "off":
        return None
    if configured:
        return Path(configured).expanduser()
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        return (
            Path(xdg_cache_home).expanduser()
            / "spaghetti-extractor"
            / "stage-a-relational-v1"
        )
    home = os.environ.get("HOME")
    if home and home != "/homeless-shelter":
        return (
            Path(home).expanduser()
            / ".cache"
            / "spaghetti-extractor"
            / "stage-a-relational-v1"
        )
    temporary = os.environ.get("TMPDIR")
    if temporary:
        return (
            Path(temporary)
            / "spaghetti-extractor-cache"
            / "stage-a-relational-v1"
        )
    return None


def _publish_persistent_olean(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _persistent_olean_path(
    lean_dir: Path,
    bundle: str,
    source: Path,
    dependencies: list[Path],
) -> Path | None:
    cache_root = _relational_cache_dir()
    if cache_root is None:
        return None
    lean = shutil.which("lean") or "lean-unavailable"
    key = sha256_bytes(
        json.dumps(
            {
                "format": "stage-a-relational-olean-cache-v5",
                "bundle": bundle,
                "source_sha256": sha256_file(source),
                "dependency_source_closure": _lean_dependency_source_closure(source),
                "dependencies": [
                    {
                        "module": dependency.stem,
                        "source_sha256": sha256_file(dependency.with_suffix(".lean")),
                        "olean_sha256": (
                            sha256_file(dependency) if dependency.exists() else None
                        ),
                    }
                    for dependency in dependencies
                ],
                "lean": lean,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    return cache_root / "lean-oleans" / f"{bundle}-{key}.olean"


def _lean_dependency_source_closure(source: Path) -> list[dict[str, str]]:
    stage_a = source.parent
    visited: set[str] = set()
    closure: list[dict[str, str]] = []

    def visit(module_source: Path) -> None:
        module = module_source.stem
        if module in visited:
            return
        visited.add(module)
        if not module_source.is_file():
            return
        imports = list(
            dict.fromkeys(
                re.findall(
                    r"^import StageA\.([A-Za-z0-9_]+)$",
                    module_source.read_text(encoding="utf-8"),
                    re.MULTILINE,
                )
            )
        )
        for imported in imports:
            imported_source = stage_a / f"{imported}.lean"
            if imported not in visited and imported_source.is_file():
                closure.append(
                    {
                        "module": imported,
                        "source_sha256": sha256_file(imported_source),
                    }
                )
                visit(imported_source)

    visit(source)
    return sorted(closure, key=lambda row: row["module"])


def _precompiled_kernel_olean(source: Path, module: str) -> Path | None:
    configured = os.environ.get(
        "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL"
    )
    if not configured:
        return None
    stage_a = Path(configured).expanduser() / "StageA"
    precompiled_source = stage_a / f"{module}.lean"
    precompiled_output = stage_a / f"{module}.olean"
    if (
        not precompiled_source.is_file()
        or not precompiled_output.is_file()
        or sha256_file(precompiled_source) != sha256_file(source)
    ):
        return None
    return precompiled_output


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _run_lean_relational(
    lean_dir: Path,
    *,
    bundle: str = "RelationalBundle",
    cancel_event: Event | None = None,
    reuse_bundle_cache: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    command_elapsed: list[float] = []

    def finish(payload: dict[str, Any]) -> dict[str, Any]:
        payload["elapsed_seconds"] = round(time.monotonic() - started, 3)
        payload["command_elapsed_seconds"] = command_elapsed
        return payload

    lean = shutil.which("lean")
    if lean is None:
        return finish(
            {
                "status": "unavailable",
                "returncode": None,
                "stdout": "",
                "stderr": "",
            }
        )
    stage_a_dir = lean_dir / "StageA"
    commands: list[list[str]] = []
    module_imports: dict[str, list[str]] = {}
    module_order: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit_module(module: str) -> None:
        if module in visited:
            return
        if module in visiting:
            raise StageAInputError(
                f"cyclic generated Lean import involving StageA.{module}"
            )
        source = stage_a_dir / f"{module}.lean"
        if not source.is_file():
            raise StageAInputError(
                f"missing generated Lean module StageA.{module}: {source}"
            )
        visiting.add(module)
        imports = list(
            dict.fromkeys(
                re.findall(
                    r"^import StageA\.([A-Za-z0-9_]+)$",
                    source.read_text(encoding="utf-8"),
                    re.MULTILINE,
                )
            )
        )
        module_imports[module] = imports
        for imported in imports:
            visit_module(imported)
        visiting.remove(module)
        visited.add(module)
        module_order.append(module)

    try:
        visit_module(bundle)
    except StageAInputError as error:
        return finish(
            {
                "status": "failed",
                "command": [],
                "returncode": 1,
                "stdout": "",
                "stderr": str(error),
            }
        )

    stdout: list[str] = []
    stderr: list[str] = []
    for module in module_order:
        source = stage_a_dir / f"{module}.lean"
        output = stage_a_dir / f"{module}.olean"
        dependency_outputs = [
            stage_a_dir / f"{dependency}.olean"
            for dependency in module_imports[module]
        ]
        if module != bundle and (
            _lean_output_current(source, output)
            and all(
                _lean_output_current(dependency, output)
                for dependency in dependency_outputs
            )
        ):
            continue
        precompiled_output = _precompiled_kernel_olean(source, module)
        if precompiled_output is not None:
            shutil.copyfile(precompiled_output, output)
            os.utime(output, None)
            continue
        cached_output = _persistent_olean_path(
            lean_dir, module, source, dependency_outputs
        )
        audited_bundle = bundle in {
            "RelationalBundle",
            "RelationalAcceptance",
            "RelationalCounterexample",
        }
        may_reuse = module != bundle or (reuse_bundle_cache and not audited_bundle)
        if may_reuse and cached_output is not None and cached_output.exists():
            shutil.copyfile(cached_output, output)
            os.utime(output, None)
            continue
        command = [
            lean,
            *_lean_memory_arguments(),
            "-o",
            f"StageA/{module}.olean",
            f"StageA/{module}.lean",
        ]
        commands.append(command)
        if cancel_event is not None and cancel_event.is_set():
            return finish(
                {
                    "status": "cancelled",
                    "command": commands,
                    "failed_command": command,
                    "returncode": None,
                    "stdout": "".join(stdout),
                    "stderr": "".join(stderr),
                }
            )
        command_started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        deadline = command_started + 300
        while True:
            if cancel_event is not None and cancel_event.is_set():
                _terminate_process_group(process)
                completed_stdout, completed_stderr = process.communicate()
                command_elapsed.append(
                    round(time.monotonic() - command_started, 3)
                )
                return finish(
                    {
                        "status": "cancelled",
                        "command": commands,
                        "failed_command": command,
                        "returncode": process.returncode,
                        "stdout": "".join(stdout) + completed_stdout,
                        "stderr": "".join(stderr) + completed_stderr,
                    }
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                completed_stdout, completed_stderr = process.communicate()
                command_elapsed.append(
                    round(time.monotonic() - command_started, 3)
                )
                return finish(
                    {
                        "status": "timeout",
                        "command": commands,
                        "failed_command": command,
                        "returncode": None,
                        "stdout": "".join(stdout) + completed_stdout,
                        "stderr": "".join(stderr) + completed_stderr,
                    }
                )
            try:
                completed_stdout, completed_stderr = process.communicate(
                    timeout=min(0.2, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                continue
        command_elapsed.append(round(time.monotonic() - command_started, 3))
        stdout.append(completed_stdout)
        stderr.append(completed_stderr)
        if process.returncode != 0:
            return finish(
                {
                    "status": "failed",
                    "command": commands,
                    "failed_command": command,
                    "returncode": process.returncode,
                    "stdout": "".join(stdout),
                    "stderr": "".join(stderr),
                }
            )
        if cached_output is not None:
            _publish_persistent_olean(output, cached_output)
    checked_sources = [stage_a_dir / f"{module}.lean" for module in module_order]
    unchecked = [
        str(path)
        for path in checked_sources
        if re.search(
            r"\b(?:sorry|axiom|unsafe)\b", path.read_text(encoding="utf-8")
        )
    ]
    if unchecked:
        return finish(
            {
                "status": "unchecked_marker",
                "command": commands,
                "returncode": 1,
                "stdout": "".join(stdout),
                "stderr": "unchecked Lean marker in: " + ", ".join(unchecked),
            }
        )
    if bundle in {
        "RelationalBundle",
        "RelationalAcceptance",
        "RelationalCounterexample",
    }:
        combined = "".join(stdout) + "\n" + "".join(stderr)
        match = re.search(r"depends on axioms: \[(.*?)\]", combined, re.DOTALL)
        if match is None:
            return finish(
                {
                    "status": "axioms_missing",
                    "command": commands,
                    "returncode": 1,
                    "stdout": "".join(stdout),
                    "stderr": "".join(stderr),
                }
            )
        axioms = {
            item.strip()
            for item in match.group(1).replace("\n", " ").split(",")
            if item.strip()
        }
        if not axioms.issubset(RELATIONAL_APPROVED_AXIOMS):
            return finish(
                {
                    "status": "unapproved_axiom",
                    "command": commands,
                    "returncode": 1,
                    "stdout": "".join(stdout),
                    "stderr": "unapproved axioms: "
                    + ", ".join(sorted(axioms - RELATIONAL_APPROVED_AXIOMS)),
                }
            )
    return finish(
        {
            "status": "checked",
            "command": commands,
            "returncode": 0,
            "stdout": "".join(stdout),
            "stderr": "".join(stderr),
        }
    )


def _lean_output_current(source: Path, output: Path) -> bool:
    try:
        return output.stat().st_mtime_ns >= source.stat().st_mtime_ns
    except OSError:
        return False
