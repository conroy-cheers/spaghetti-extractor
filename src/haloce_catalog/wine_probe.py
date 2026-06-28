from __future__ import annotations

import os
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from .catalog import build_catalog, runtime_provenance, tool_versions
from .coverage import prove_halo_trace
from .db import connect, initialize
from .labels import ensure_label, trace_probe_label
from .util import json_dumps, utc_now


def probe_wine_trace_matrix(
    *,
    smoke_root: Path | None,
    smoke_exe: Path | None,
    out_dir: Path,
    wine_commands: Iterable[str],
    trace_runner: str | None = None,
    arch: str = "auto",
    timeout_seconds: int = 30,
    wine_debug: str | None = "-all",
    wait_wineserver: bool = False,
    isolate_catalog_build: bool = False,
    isolate_trace_proof: bool = False,
) -> dict[str, Any]:
    """Run the public 32-bit PE trace proof across candidate Wine commands."""

    resolved_exe = _resolve_smoke_exe(smoke_root=smoke_root, smoke_exe=smoke_exe)
    resolved_root = _resolve_smoke_root(resolved_exe, smoke_root=smoke_root)
    commands = [command for command in wine_commands if command.strip()]
    if not commands:
        commands = ["wine"]

    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "catalog.db"
    trace_dir = out_dir / "traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    catalog = _build_probe_catalog(resolved_root, db_path, out_dir, isolated=isolate_catalog_build)

    results = []
    with _temporary_winedebug(wine_debug):
        for index, command in enumerate(commands, start=1):
            command_parts = shlex.split(command)
            if not command_parts:
                continue
            wine_version = _wine_command_version(command_parts)
            traced_command_parts, launch_info = _traceable_wine_command(command_parts)
            test_id = f"wine-probe-{index:02d}-{_safe_name(command_parts[0])}"
            trace_log = trace_dir / f"{test_id}.jsonl"
            wine_env, wine_prefix_isolated = _candidate_wine_env(out_dir, test_id)
            with _temporary_env(wine_env):
                direct_launch = _run_direct_wine_smoke([*command_parts, str(resolved_exe)], timeout_seconds)
                wineserver_wait = (
                    _run_wineserver_wait(command_parts, timeout_seconds)
                    if wait_wineserver
                    else {"command": "", "ok": True, "skipped": True, "reason": "disabled"}
                )
                proof = _prove_trace_for_probe(
                    db_path,
                    trace_log,
                    test_id,
                    [*traced_command_parts, str(resolved_exe)],
                    expected_filename=resolved_exe.name,
                    arch=arch,
                    trace_runner=trace_runner,
                    timeout_seconds=timeout_seconds,
                    isolated=isolate_trace_proof,
                )
                wine_prefix = os.environ.get("WINEPREFIX", "")
                wine_arch = os.environ.get("WINEARCH", "")
            _record_probe_result(
                db_path,
                probe_id=test_id,
                probe_kind="wine-dynamorio-pe32",
                command=proof.get("command") or [*command_parts, str(resolved_exe)],
                proof=proof,
                provenance={
                    **runtime_provenance(),
                    "arch": arch,
                    "smoke_root": str(resolved_root),
                    "smoke_exe": str(resolved_exe),
                    "trace_runner": trace_runner or "",
                    "timeout_seconds": timeout_seconds,
                    "wait_wineserver": wait_wineserver,
                    "isolate_catalog_build": isolate_catalog_build,
                    "isolate_trace_proof": isolate_trace_proof,
                    "wine_command": command,
                    "trace_wine_command": shlex.join(traced_command_parts),
                    "wine_version": wine_version,
                    "wine_debug": os.environ.get("WINEDEBUG", ""),
                    "wine_prefix": wine_prefix,
                    "wine_prefix_isolated": wine_prefix_isolated,
                    "wine_arch": wine_arch,
                    "direct_launch": direct_launch,
                    "wineserver_wait": wineserver_wait,
                    **launch_info,
                },
            )
            results.append(
                {
                    "wine_command": command,
                    "ok": proof["ok"],
                    "failures": proof["failures"],
                    "returncode": proof["returncode"],
                    "timed_out": proof["timed_out"],
                    "trace_log": proof["trace_log"],
                    "raw_trace": proof["raw_trace"],
                    "mapped": proof["mapped"],
                    "stdout": proof["stdout"],
                    "stderr": proof["stderr"],
                    "wine_version": wine_version,
                    "direct_launch": direct_launch,
                    "trace_wine_command": shlex.join(traced_command_parts),
                    "wine_prefix": wine_prefix,
                    "wine_prefix_isolated": wine_prefix_isolated,
                    "wine_arch": wine_arch,
                    "wineserver_wait": wineserver_wait,
                    **launch_info,
                }
            )

    return {
        "ok": any(result["ok"] for result in results),
        "smoke_root": str(resolved_root),
        "smoke_exe": str(resolved_exe),
        "db": str(db_path),
        "catalog": catalog,
        "probes": {
            "total": len(results),
            "passed": sum(1 for result in results if result["ok"]),
            "failed": sum(1 for result in results if not result["ok"]),
        },
        "results": results,
    }


def _build_probe_catalog(root: Path, db_path: Path, out_dir: Path, *, isolated: bool) -> dict[str, Any]:
    if not isolated:
        return build_catalog(root, db_path, static_depth="none")

    report_dir = out_dir / "catalog-build-reports"
    catalog_cli = shutil.which("wincr") or shutil.which("haloce-catalog")
    command = [catalog_cli, "build"] if catalog_cli else [sys.executable, "-m", "wincr", "build"]
    command.extend(
        [
            "--install-root",
            str(root),
            "--db",
            str(db_path),
            "--report-dir",
            str(report_dir),
            "--static-depth",
            "none",
        ]
    )
    proc = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        return {
            "root": str(root),
            "errors": [f"isolated catalog build exited with {proc.returncode}"],
            "command": command,
            "stdout": _short_text(proc.stdout),
            "stderr": _short_text(proc.stderr),
        }
    try:
        payload = json.loads(proc.stdout[proc.stdout.index("{") :])
    except (ValueError, json.JSONDecodeError) as exc:
        return {
            "root": str(root),
            "errors": [f"isolated catalog build returned invalid JSON: {exc}"],
            "command": command,
            "stdout": _short_text(proc.stdout),
            "stderr": _short_text(proc.stderr),
        }
    catalog = payload.get("catalog")
    if isinstance(catalog, dict):
        catalog = dict(catalog)
        catalog["isolated_build"] = True
        catalog["isolated_build_command"] = command
        catalog["isolated_build_stderr"] = _short_text(proc.stderr)
        return catalog
    return {
        "root": str(root),
        "errors": ["isolated catalog build JSON did not contain a catalog object"],
        "command": command,
        "stdout": _short_text(proc.stdout),
        "stderr": _short_text(proc.stderr),
    }


def _prove_trace_for_probe(
    db_path: Path,
    trace_log: Path,
    test_id: str,
    app: list[str],
    *,
    expected_filename: str,
    arch: str,
    trace_runner: str | None,
    timeout_seconds: int,
    isolated: bool,
) -> dict[str, Any]:
    if not isolated:
        return prove_halo_trace(
            db_path,
            trace_log,
            test_id,
            app,
            expected_filename=expected_filename,
            arch=arch,
            trace_runner=trace_runner,
            timeout_seconds=timeout_seconds,
            allow_timeout=False,
        )

    catalog_cli = shutil.which("wincr") or shutil.which("haloce-catalog")
    command = [catalog_cli, "prove-trace"] if catalog_cli else [sys.executable, "-m", "wincr", "prove-trace"]
    command.extend(
        [
            "--db",
            str(db_path),
            "--out",
            str(trace_log),
            "--test-id",
            test_id,
            "--expected-filename",
            expected_filename,
            "--arch",
            arch,
            "--timeout-seconds",
            str(timeout_seconds),
            "--fail-on-timeout",
            "--report-dir",
            str(trace_log.parent.parent / "trace-proof-reports"),
        ]
    )
    if trace_runner:
        command.extend(["--trace-runner", trace_runner])
    command.extend(["--", *app])
    proc = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        payload = json.loads(proc.stdout[proc.stdout.index("{") :])
    except (ValueError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "test_id": test_id,
            "suite": "trace",
            "command": command,
            "pretraced": False,
            "returncode": proc.returncode,
            "timed_out": False,
            "stdout": _short_text(proc.stdout),
            "stderr": _short_text(proc.stderr),
            "trace_log": str(trace_log),
            "expected": {"filename": expected_filename},
            "raw_trace": {},
            "ingested": {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0},
            "mapped": {"blocks": 0, "cfg_edges": 0, "call_edges": 0},
            "failures": [f"isolated trace proof returned invalid JSON: {exc}"],
        }
    proof = payload.get("trace_proof")
    if not isinstance(proof, dict):
        return {
            "ok": False,
            "test_id": test_id,
            "suite": "trace",
            "command": command,
            "pretraced": False,
            "returncode": proc.returncode,
            "timed_out": False,
            "stdout": _short_text(proc.stdout),
            "stderr": _short_text(proc.stderr),
            "trace_log": str(trace_log),
            "expected": {"filename": expected_filename},
            "raw_trace": {},
            "ingested": {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0},
            "mapped": {"blocks": 0, "cfg_edges": 0, "call_edges": 0},
            "failures": ["isolated trace proof JSON did not contain a trace_proof object"],
        }
    proof = dict(proof)
    proof["isolated_trace_proof"] = True
    proof["isolated_trace_command"] = command
    proof["isolated_trace_returncode"] = proc.returncode
    proof["isolated_trace_stderr"] = _short_text(proc.stderr)
    return proof


def _resolve_smoke_exe(*, smoke_root: Path | None, smoke_exe: Path | None) -> Path:
    if smoke_exe is not None:
        resolved = smoke_exe.resolve()
        if resolved.is_file():
            return resolved
        raise FileNotFoundError(f"smoke executable not found: {smoke_exe}")
    if smoke_root is None:
        raise ValueError("pass --smoke-root or --smoke-exe")
    candidate = smoke_root / "bin" / "halo-trace-win32-smoke.exe"
    if candidate.is_file():
        return candidate.resolve()
    wrapper = smoke_root / "bin" / "halo-trace-win32-smoke-root"
    if wrapper.is_file():
        proc = subprocess.run([str(wrapper)], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode == 0 and proc.stdout.strip():
            return _resolve_smoke_exe(smoke_root=Path(proc.stdout.strip()), smoke_exe=None)
    raise FileNotFoundError(f"smoke executable not found under {smoke_root}")


def _resolve_smoke_root(smoke_exe: Path, *, smoke_root: Path | None) -> Path:
    if smoke_root is not None:
        candidate = smoke_root / "bin" / "halo-trace-win32-smoke.exe"
        if candidate.is_file():
            return smoke_root.resolve()
    return smoke_exe.parent.parent.resolve()


def _safe_name(value: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in Path(value).name).strip("_")
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe[:48] or "wine"


def _candidate_wine_env(out_dir: Path, test_id: str) -> tuple[dict[str, str], bool]:
    if os.environ.get("WINEPREFIX"):
        return {}, False
    prefix = (out_dir / "wineprefixes" / test_id).resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    return {"WINEPREFIX": str(prefix)}, True


def _wine_command_version(command_parts: list[str]) -> str | None:
    try:
        proc = subprocess.run(
            [*command_parts, "--version"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0][:200]


def _run_direct_wine_smoke(command_parts: list[str], timeout_seconds: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="haloce-wine-direct-") as tmp:
        stdout_path = Path(tmp) / "stdout.txt"
        stderr_path = Path(tmp) / "stderr.txt"
        try:
            with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
                proc = subprocess.run(
                    command_parts,
                    check=False,
                    text=True,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout_seconds,
                )
        except subprocess.TimeoutExpired:
            return {
                "command": shlex.join(command_parts),
                "ok": False,
                "returncode": None,
                "timed_out": True,
                "stdout": _short_text(_read_text(stdout_path)),
                "stderr": _short_text(_read_text(stderr_path)),
            }
        except OSError as exc:
            return {
                "command": shlex.join(command_parts),
                "ok": False,
                "returncode": None,
                "timed_out": False,
                "stdout": _short_text(_read_text(stdout_path)),
                "stderr": str(exc)[:4000],
            }
        return {
            "command": shlex.join(command_parts),
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "timed_out": False,
            "stdout": _short_text(_read_text(stdout_path)),
            "stderr": _short_text(_read_text(stderr_path)),
        }


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _run_wineserver_wait(command_parts: list[str], timeout_seconds: int) -> dict[str, Any]:
    executable = _resolve_executable(command_parts[0]) if command_parts else None
    if executable is None:
        return {"command": "", "ok": False, "skipped": True, "reason": "wine command not found"}
    wineserver = executable.parent / "wineserver"
    if not wineserver.is_file():
        return {"command": str(wineserver), "ok": False, "skipped": True, "reason": "wineserver not found"}
    command = [str(wineserver), "-w"]
    try:
        proc = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "command": shlex.join(command),
            "ok": False,
            "skipped": False,
            "returncode": None,
            "timed_out": True,
            "stdout": _short_text(exc.stdout),
            "stderr": _short_text(exc.stderr),
        }
    except OSError as exc:
        return {
            "command": shlex.join(command),
            "ok": False,
            "skipped": False,
            "returncode": None,
            "timed_out": False,
            "stdout": "",
            "stderr": str(exc)[:4000],
        }
    return {
        "command": shlex.join(command),
        "ok": proc.returncode == 0,
        "skipped": False,
        "returncode": proc.returncode,
        "timed_out": False,
        "stdout": _short_text(proc.stdout),
        "stderr": _short_text(proc.stderr),
    }


def _short_text(value: str | bytes | None, limit: int = 4000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[:limit]


def _traceable_wine_command(command_parts: list[str]) -> tuple[list[str], dict[str, str]]:
    """Resolve Nix Wine shell wrappers to their ELF WINELOADER for DynamoRIO."""

    executable = _resolve_executable(command_parts[0])
    if executable is None:
        return command_parts, {}
    loader = _wine_loader_from_wrapper(executable)
    if loader is None:
        return command_parts, {}
    return [str(loader), *command_parts[1:]], {
        "wine_wrapper": str(executable),
        "wine_loader": str(loader),
    }


def _resolve_executable(value: str) -> Path | None:
    path = Path(value)
    if path.is_file():
        return path
    found = shutil.which(value)
    return Path(found) if found else None


def _wine_loader_from_wrapper(path: Path) -> Path | None:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if not data.startswith("#!"):
        return None
    for line in data.splitlines()[:80]:
        line = line.strip()
        if not line.startswith("export WINELOADER="):
            continue
        try:
            parts = shlex.split(line.split("=", 1)[1])
        except ValueError:
            return None
        if not parts:
            return None
        loader = Path(parts[0])
        if loader.is_file():
            return loader
    return None


def _record_probe_result(
    db_path: Path,
    *,
    probe_id: str,
    probe_kind: str,
    command: list[str],
    proof: dict[str, Any],
    provenance: dict[str, object],
) -> None:
    started = utc_now()
    finished = utc_now()
    status = "pass" if proof.get("ok") else "fail"
    command_text = shlex.join(str(part) for part in command)
    label = trace_probe_label(probe_id, command_text, started)
    expected = proof.get("expected") if isinstance(proof.get("expected"), dict) else {}
    conn = connect(db_path)
    initialize(conn)
    try:
        with conn:
            ensure_label(
                conn,
                label,
                "trace_probe",
                probe_id,
                f"{probe_kind} {status} trace compatibility probe",
                created_at=started,
            )
            conn.execute(
                """
                INSERT INTO trace_probe_results(
                  label, probe_id, probe_kind, command, status, started_at, finished_at,
                  trace_log, expected_filename, expected_sha256, returncode, timed_out,
                  raw_trace_json, mapped_json, failures_json, stdout, stderr,
                  tool_versions_json, provenance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    label,
                    probe_id,
                    probe_kind,
                    command_text,
                    status,
                    started,
                    finished,
                    proof.get("trace_log"),
                    expected.get("filename"),
                    expected.get("sha256"),
                    proof.get("returncode"),
                    1 if proof.get("timed_out") else 0,
                    json_dumps(proof.get("raw_trace") or {}),
                    json_dumps(proof.get("mapped") or {}),
                    json_dumps(proof.get("failures") or []),
                    str(proof.get("stdout") or ""),
                    str(proof.get("stderr") or ""),
                    json_dumps(tool_versions()),
                    json_dumps(provenance),
                ),
            )
    finally:
        conn.close()


@contextmanager
def _temporary_winedebug(value: str | None):
    if value is None or "WINEDEBUG" in os.environ:
        yield
        return
    os.environ["WINEDEBUG"] = value
    try:
        yield
    finally:
        os.environ.pop("WINEDEBUG", None)


@contextmanager
def _temporary_env(updates: dict[str, str]):
    original = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
