from __future__ import annotations

import os
import shutil
from pathlib import Path


DEFAULT_GHIDRA_SCRIPT = "SpaghettiExtractorStageBExport.java"


def _resolve_analyze_headless(value: str | None) -> str:
    if value:
        return value
    env_value = os.environ.get("SPAGHETTI_EXTRACTOR_GHIDRA_HEADLESS")
    if env_value:
        return env_value
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    for env_name in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        ghidra_root = os.environ.get(env_name)
        if not ghidra_root:
            continue
        candidate = Path(ghidra_root) / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    return "analyzeHeadless"


def _resolve_script_path(value: Path | None) -> Path:
    candidates: list[Path] = []
    if value is not None:
        candidates.append(Path(value))
    candidates.append(Path("tools/ghidra"))
    candidates.append(Path(__file__).resolve().parents[2] / "tools" / "ghidra")
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    searched = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"Ghidra script path not found; searched: {searched}")
