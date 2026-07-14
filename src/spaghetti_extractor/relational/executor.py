from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from threading import Event
from typing import Any

from ..stage_binary import StageAInputError
from ..util import sha256_bytes, sha256_file, write_json
from .build import _read_json
from .schema import RELATIONAL_ACCEPTANCE_THEOREM, RELATIONAL_APPROVED_AXIOMS


def _relational_cache_dir() -> Path | None:
    configured = os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE")
    if configured == "off":
        return None
    if configured:
        return Path(configured).expanduser()
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        return Path(xdg_cache_home).expanduser() / "spaghetti-extractor" / "stage-a-relational-v1"
    home = os.environ.get("HOME")
    if home and home != "/homeless-shelter":
        return Path(home).expanduser() / ".cache" / "spaghetti-extractor" / "stage-a-relational-v1"
    temporary = os.environ.get("TMPDIR")
    if temporary:
        return Path(temporary) / "spaghetti-extractor-cache" / "stage-a-relational-v1"
    return None

def _failed_shard_hint_path(lean_dir: Path) -> Path | None:
    cache_root = _relational_cache_dir()
    if cache_root is None:
        return None
    sources = [
        lean_dir / "StageA" / "RelationalProofOriginal.lean",
        lean_dir / "StageA" / "RelationalProofCandidate.lean",
        lean_dir / "StageA" / "RelationalBundle.lean",
    ]
    if not all(source.is_file() for source in sources):
        return None
    key = sha256_bytes(json.dumps({
        "format": "stage-a-relational-failed-shard-key-v1",
        "sources": [sha256_file(source) for source in sources],
    }, sort_keys=True, separators=(",", ":")).encode())
    return cache_root / "failed-shards" / f"{key}.json"

def _relational_proof_jobs() -> int:
    configured = os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PROOF_JOBS")
    if configured is not None:
        return max(1, int(configured))
    cpu_jobs = min(16, os.cpu_count() or 1)
    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="ascii")
        match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", meminfo, re.MULTILINE)
        memory_jobs = max(1, int(match.group(1)) // (3 * 1024 * 1024)) if match else cpu_jobs
    except OSError:
        memory_jobs = cpu_jobs
    return max(1, min(cpu_jobs, memory_jobs))

def _compile_relational_kernel(lean_dir: Path) -> dict[str, Any]:
    return _run_lean_relational(
        lean_dir, bundle="Relational", reuse_bundle_cache=True
    )

def _compile_formal_kernel(lean_dir: Path) -> dict[str, Any]:
    source = lean_dir / "StageA" / "Formal.lean"
    output = lean_dir / "StageA" / "Formal.olean"
    if _lean_output_current(source, output):
        return {"status": "checked", "source": "current_olean"}
    cached_output = _persistent_olean_path(lean_dir, "Formal", source, [])
    if cached_output is not None and cached_output.exists():
        shutil.copyfile(cached_output, output)
        os.utime(output, None)
        return {"status": "checked", "source": "persistent_olean_cache"}
    lean = shutil.which("lean")
    if lean is None:
        return {"status": "unavailable", "returncode": None, "stdout": "", "stderr": ""}
    try:
        completed = subprocess.run(
            [lean, "-o", "StageA/Formal.olean", "StageA/Formal.lean"],
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "timeout", "returncode": None,
            "stdout": exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout or "",
            "stderr": exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr or "",
        }
    result = {
        "status": "checked" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if result["status"] == "checked" and cached_output is not None:
        _publish_persistent_olean(output, cached_output)
    return result


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

def _run_lean_relational_cached(
    lean_dir: Path,
    *,
    bundle: str,
    cancel_event: Event | None = None,
) -> dict[str, Any]:
    if cancel_event is not None and cancel_event.is_set():
        return {"status": "cancelled", "returncode": None, "stdout": "", "stderr": ""}
    return _run_lean_relational(
        lean_dir,
        bundle=bundle,
        cancel_event=cancel_event,
        reuse_bundle_cache=True,
    )

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
    key = sha256_bytes(json.dumps({
        "format": "stage-a-relational-olean-cache-v3",
        "bundle": bundle,
        "source_sha256": sha256_file(source),
        "formal_sha256": sha256_file(lean_dir / "StageA" / "Formal.lean"),
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
    }, sort_keys=True, separators=(",", ":")).encode())
    return cache_root / "lean-oleans" / f"{bundle}-{key}.olean"

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
        return finish({"status": "unavailable", "returncode": None, "stdout": "", "stderr": ""})
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
        imports = list(dict.fromkeys(re.findall(
            r"^import StageA\.([A-Za-z0-9_]+)$",
            source.read_text(encoding="utf-8"),
            re.MULTILINE,
        )))
        module_imports[module] = imports
        for imported in imports:
            visit_module(imported)
        visiting.remove(module)
        visited.add(module)
        module_order.append(module)

    try:
        visit_module(bundle)
    except StageAInputError as error:
        return finish({
            "status": "failed",
            "command": [],
            "returncode": 1,
            "stdout": "",
            "stderr": str(error),
        })

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
            and all(_lean_output_current(dependency, output)
                    for dependency in dependency_outputs)
        ):
            continue
        cached_output = _persistent_olean_path(
            lean_dir, module, source, dependency_outputs
        )
        audited_bundle = bundle in {
            "RelationalBundle", "RelationalAcceptance", "RelationalCounterexample",
        }
        may_reuse = module != bundle or (reuse_bundle_cache and not audited_bundle)
        if may_reuse and cached_output is not None and cached_output.exists():
            shutil.copyfile(cached_output, output)
            os.utime(output, None)
            continue
        command = [
            lean, "-o", f"StageA/{module}.olean", f"StageA/{module}.lean",
        ]
        commands.append(command)
        if cancel_event is not None and cancel_event.is_set():
            return finish({
                "status": "cancelled",
                "command": commands,
                "failed_command": command,
                "returncode": None,
                "stdout": "".join(stdout),
                "stderr": "".join(stderr),
            })
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
                command_elapsed.append(round(time.monotonic() - command_started, 3))
                return finish({
                    "status": "cancelled",
                    "command": commands,
                    "failed_command": command,
                    "returncode": process.returncode,
                    "stdout": "".join(stdout) + completed_stdout,
                    "stderr": "".join(stderr) + completed_stderr,
                })
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                completed_stdout, completed_stderr = process.communicate()
                command_elapsed.append(round(time.monotonic() - command_started, 3))
                return finish({
                    "status": "timeout",
                    "command": commands,
                    "failed_command": command,
                    "returncode": None,
                    "stdout": "".join(stdout) + completed_stdout,
                    "stderr": "".join(stderr) + completed_stderr,
                })
            try:
                completed_stdout, completed_stderr = process.communicate(timeout=min(0.2, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        command_elapsed.append(round(time.monotonic() - command_started, 3))
        stdout.append(completed_stdout)
        stderr.append(completed_stderr)
        if process.returncode != 0:
            return finish({"status": "failed", "command": commands, "failed_command": command, "returncode": process.returncode, "stdout": "".join(stdout), "stderr": "".join(stderr)})
        if cached_output is not None:
            _publish_persistent_olean(output, cached_output)
    checked_sources = [stage_a_dir / f"{module}.lean" for module in module_order]
    unchecked = [
        str(path)
        for path in checked_sources
        if re.search(r"\b(?:sorry|axiom|unsafe)\b", path.read_text(encoding="utf-8"))
    ]
    if unchecked:
        return finish({
            "status": "unchecked_marker",
            "command": commands,
            "returncode": 1,
            "stdout": "".join(stdout),
            "stderr": "unchecked Lean marker in: " + ", ".join(unchecked),
        })
    if bundle in {
        "RelationalBundle", "RelationalAcceptance", "RelationalCounterexample",
    }:
        combined = "".join(stdout) + "\n" + "".join(stderr)
        match = re.search(r"depends on axioms: \[(.*?)\]", combined, re.DOTALL)
        if match is None:
            return finish({"status": "axioms_missing", "command": commands, "returncode": 1, "stdout": "".join(stdout), "stderr": "".join(stderr)})
        axioms = {item.strip() for item in match.group(1).replace("\n", " ").split(",") if item.strip()}
        if not axioms.issubset(RELATIONAL_APPROVED_AXIOMS):
            return finish({
                "status": "unapproved_axiom",
                "command": commands,
                "returncode": 1,
                "stdout": "".join(stdout),
                "stderr": "unapproved axioms: " + ", ".join(sorted(axioms - RELATIONAL_APPROVED_AXIOMS)),
            })
    return finish({"status": "checked", "command": commands, "returncode": 0, "stdout": "".join(stdout), "stderr": "".join(stderr)})

def _lean_output_current(source: Path, output: Path) -> bool:
    try:
        return output.stat().st_mtime_ns >= source.stat().st_mtime_ns
    except OSError:
        return False

def _collect_certificates(lean_dir: Path, destination: Path) -> list[dict[str, Any]]:
    files = sorted(lean_dir.glob("StageA-Relational*-region*CheckedDirectBehavior-*.lrat"))
    entries: list[dict[str, Any]] = []
    for path in files:
        match = re.search(r"region(\d+)CheckedDirect", path.name)
        if match is None:
            continue
        region_index = int(match.group(1))
        target = destination / f"region-{region_index}.lrat"
        shutil.copyfile(path, target)
        entries.append({"region_index": region_index, "kind": "lrat", "path": target.name, "sha256": sha256_file(target)})
    return entries
