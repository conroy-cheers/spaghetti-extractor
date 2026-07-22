from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

from ..util import sha256_bytes, sha256_file, write_json
from .artifacts import read_json_object as _read_json
from .lean.compiler import (
    _lean_dependency_source_closure,
    _lean_output_current,
    _persistent_olean_path,
    _precompiled_kernel_olean,
    _publish_persistent_olean,
    _relational_cache_dir,
    _run_lean_relational,
    _terminate_process_group,
)
from .schema import RELATIONAL_APPROVED_AXIOMS


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
    # Formal now imports independently cached semantic modules.  The generic
    # graph runner must restore that entire closure before reusing Formal.olean.
    return _run_lean_relational(
        lean_dir, bundle="Formal", reuse_bundle_cache=True
    )


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
