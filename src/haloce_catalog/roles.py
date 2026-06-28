from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .target import TargetConfig, load_target_config


@dataclass(frozen=True)
class RoleDecision:
    role: str
    scope: str
    reason: str


def classify_pe(relative_path: str, target_config: TargetConfig | None = None) -> RoleDecision:
    target = target_config or load_target_config()
    rel = PurePosixPath(relative_path.replace("\\", "/"))
    filename = rel.name.lower()
    lower_parts = [part.lower() for part in rel.parts]
    normalized_path = rel.as_posix().lower()

    platform = _classify_platform_or_installer(filename, lower_parts)
    if platform is not None:
        return platform

    for rule in target.binary_rules:
        names = {name.lower() for name in rule.names}
        path_markers = tuple(marker.lower() for marker in rule.path_contains)
        if names and filename not in names:
            continue
        if path_markers and not all(marker in normalized_path for marker in path_markers):
            continue
        return RoleDecision(role=rule.role, scope=rule.scope, reason=rule.reason)

    if target.unknown_directory_markers and all(marker.lower() in lower_parts for marker in target.unknown_directory_markers):
        return RoleDecision(
            role="unknown_target_directory_pe",
            scope="candidate",
            reason=f"PE file shipped in the {target.project_name} directory without a settled disposition",
        )

    return RoleDecision(role="unknown_pe", scope="candidate", reason="PE file requires explicit catalog disposition")


def _classify_platform_or_installer(filename: str, lower_parts: list[str]) -> RoleDecision | None:
    if "windows" in lower_parts:
        return RoleDecision(
            role="platform_runtime",
            scope="excluded",
            reason="Wine/Windows platform runtime from the declarative prefix",
        )

    if "common files" in lower_parts and "microsoft shared" in lower_parts:
        return RoleDecision(
            role="platform_runtime",
            scope="excluded",
            reason="Microsoft shared platform/runtime support from the declarative prefix",
        )

    if "redist" in lower_parts or "directx" in lower_parts:
        return RoleDecision(
            role="excluded_tool_or_redistributable",
            scope="excluded",
            reason=_installer_reason(filename),
        )

    if filename.endswith("haloupdate.exe"):
        return RoleDecision(
            role="excluded_tool_or_redistributable",
            scope="excluded",
            reason="updater tool, out of runtime scope",
        )

    return None


def _installer_reason(filename: str) -> str:
    reasons = {
        "dsetup.dll": "DirectX installer support DLL, out of runtime scope",
        "dxwebsetup.exe": "DirectX web installer, out of runtime scope",
        "instmsia.exe": "MSI redistributable installer, out of runtime scope",
        "instmsiw.exe": "MSI redistributable installer, out of runtime scope",
    }
    return reasons.get(filename, "redistributable or installer support component")
