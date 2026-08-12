"""Fast environment diagnosis with direct remediation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import os
from typing import Callable, Mapping, Sequence

from .diagnostics import Diagnostic
from .discovery import build_impact_index
from .fixtures import FIXTURE_ENV, FixtureCatalog


@dataclass(frozen=True, slots=True)
class DoctorReport:
    status: str
    checks: tuple[Diagnostic, ...]

    def as_dict(self) -> dict[str, object]:
        counts = {severity: sum(row.severity == severity for row in self.checks) for severity in ("error", "warning", "info")}
        return {
            "format": "spaghetti-extractor-testkit-doctor-v1",
            "status": self.status,
            "counts": counts,
            "checks": [row.as_dict() for row in self.checks],
        }


def _run(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)


def _nix_checks(repository: Path, runner: Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]) -> list[Diagnostic]:
    nix = shutil.which("nix")
    if nix is None:
        return [
            Diagnostic(
                "error",
                "nix_missing",
                "Nix is not available",
                remediation="Enter the repository development shell before running tests.",
                example="nix develop",
            )
        ]
    version = runner((nix, "--version"), repository)
    if version.returncode != 0:
        return [Diagnostic("error", "nix_unusable", version.stderr.strip() or "nix --version failed", remediation="Repair the Nix installation before running the suite.")]
    checks = [Diagnostic("info", "nix_version", version.stdout.strip())]
    config = runner((nix, "config", "show", "--json"), repository)
    if config.returncode != 0:
        checks.append(Diagnostic("warning", "nix_config_unavailable", "could not inspect Nix feature configuration", remediation="Run `nix config show --json` and repair the reported error."))
        return checks
    try:
        payload = json.loads(config.stdout)
    except json.JSONDecodeError:
        checks.append(Diagnostic("warning", "nix_config_invalid", "Nix returned non-JSON configuration", remediation="Upgrade to the pinned Nix 2.35 environment."))
        return checks
    feature_value = payload.get("experimental-features", {})
    if isinstance(feature_value, Mapping):
        feature_value = feature_value.get("value", "")
    features = (
        {str(item) for item in feature_value}
        if isinstance(feature_value, list)
        else set(str(feature_value).split())
    )
    missing = sorted({"ca-derivations", "nix-command"} - features)
    if missing:
        checks.append(
            Diagnostic(
                "error",
                "nix_features_missing",
                f"required Nix features are disabled: {', '.join(missing)}",
                remediation="Enable `nix-command ca-derivations` in the active Nix configuration.",
            )
        )
    else:
        checks.append(Diagnostic("info", "nix_features", "nix-command and ca-derivations are enabled"))
    builders_value = payload.get("builders", {})
    if isinstance(builders_value, Mapping):
        builders_value = builders_value.get("value", "")
    if not str(builders_value).strip():
        checks.append(Diagnostic("warning", "remote_builders_missing", "no remote builders are configured", remediation="Configure the project builder file for clean-suite parallelism; local incremental planning still works."))
    else:
        checks.append(Diagnostic("info", "remote_builders", "remote builders are configured"))
    return checks


def run_doctor(
    repository: Path,
    *,
    environment: Mapping[str, str] | None = None,
    runner: Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]] = _run,
) -> DoctorReport:
    repository = repository.resolve()
    checks: list[Diagnostic] = []
    if sys.version_info < (3, 11):
        checks.append(Diagnostic("error", "python_too_old", f"Python 3.11 or newer is required; running {platform.python_version()}", remediation="Enter the Nix development shell."))
    else:
        checks.append(Diagnostic("info", "python_version", f"Python {platform.python_version()}"))
    if not (repository / "flake.nix").is_file():
        checks.append(Diagnostic("error", "repository_root_invalid", "flake.nix is absent", location=str(repository), remediation="Pass the Spaghetti Extractor repository root with `--repository`."))
    else:
        checks.append(Diagnostic("info", "repository_root", str(repository)))
    try:
        index = build_impact_index(repository, strict_policy=False)
        checks.append(Diagnostic("info", "test_discovery", f"discovered {len(index.tests)} tests in {len({row.shard for row in index.tests})} stable shards"))
        checks.extend(index.diagnostics)
    except ValueError as exc:
        diagnostics = getattr(exc, "diagnostics", ())
        checks.extend(diagnostics or (Diagnostic("error", "test_discovery_failed", str(exc)),))
    checks.extend(_nix_checks(repository, runner))
    environment = dict(os.environ if environment is None else environment)
    if FIXTURE_ENV in environment:
        try:
            catalog = FixtureCatalog.from_environment(environment, repository=repository)
            available = sum(bool(catalog.describe(row.id)["available"]) for row in catalog.definitions())
            checks.append(Diagnostic("info", "fixture_catalog", f"{available} shared fixtures are available"))
        except ValueError as exc:
            checks.extend(getattr(exc, "diagnostics", (Diagnostic("error", "fixture_catalog_invalid", str(exc)),)))
    else:
        checks.append(Diagnostic("info", "fixture_catalog", "no fixture environment is active; pure tests remain available"))
    status = "error" if any(row.severity == "error" for row in checks) else "warning" if any(row.severity == "warning" for row in checks) else "ok"
    return DoctorReport(status=status, checks=tuple(checks))


__all__ = ["DoctorReport", "run_doctor"]
