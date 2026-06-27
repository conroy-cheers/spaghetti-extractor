from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class RoleDecision:
    role: str
    scope: str
    reason: str


INCLUDED_RUNTIME = {
    "haloce.exe": "playable client executable",
    "haloceded.exe": "dedicated server executable",
    "keystone.dll": "GameSpy/Keystone runtime service component imported by the game",
    "strings.dll": "closed runtime support DLL shipped in the game directory",
    "binkw32.dll": "closed Bink video runtime imported by startup/video paths",
}

CANDIDATE_RUNTIME = {
    "ksimeui.dll": "Keystone UI support DLL; keep visible until runtime tracing proves it unused",
    "mgspid.dll": "Microsoft game service/PID support DLL; keep visible until tracing proves it unused",
    "patchw32.dll": "patch/runtime support DLL; keep visible until tracing proves it unused",
}

SOURCE_AVAILABLE_EXTERNAL = {
    "ogg.dll": "source-available Ogg dependency",
    "vorbis.dll": "source-available Vorbis dependency",
    "vorbisfile.dll": "source-available Vorbisfile dependency",
}

VENDOR_REPLACEABLE = {
    "msvcr71.dll": "vendor CRT runtime; model interface behavior rather than decompile",
}

EXCLUDED_TOOLS = {
    "gsarcade.exe": "GameSpy Arcade launcher, not required for clean-room runtime oracle",
    "chktrust.exe": "installer/update trust helper, not gameplay/server runtime",
    "haloupdate.exe": "updater tool, out of runtime scope",
    "uninstal.exe": "uninstaller tool, out of runtime scope",
    "dw15.exe": "Watson crash-reporting tool, out of runtime scope",
    "dsetup.dll": "DirectX installer support DLL, out of runtime scope",
    "eula.dll": "installer/EULA component, out of runtime scope",
    "pidgen.dll": "installer product-key helper, out of runtime scope",
    "setupenu.dll": "installer UI/resource component, out of runtime scope",
    "shfolder.exe": "redistributable installer helper, out of runtime scope",
    "dxwebsetup.exe": "DirectX web installer, out of runtime scope",
    "instmsia.exe": "MSI redistributable installer, out of runtime scope",
    "instmsiw.exe": "MSI redistributable installer, out of runtime scope",
}


def classify_pe(relative_path: str) -> RoleDecision:
    rel = PurePosixPath(relative_path.replace("\\", "/"))
    filename = rel.name.lower()
    lower_parts = [part.lower() for part in rel.parts]

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
            reason=EXCLUDED_TOOLS.get(filename, "redistributable or installer support component"),
        )

    if filename.endswith("haloupdate.exe"):
        return RoleDecision(
            role="excluded_tool_or_redistributable",
            scope="excluded",
            reason="updater tool, out of runtime scope",
        )

    if "watson" in lower_parts:
        return RoleDecision(
            role="excluded_tool_or_redistributable",
            scope="excluded",
            reason=EXCLUDED_TOOLS.get(filename, "Watson crash-reporting component"),
        )

    if filename in INCLUDED_RUNTIME:
        return RoleDecision(role="closed_runtime", scope="included", reason=INCLUDED_RUNTIME[filename])

    if filename in CANDIDATE_RUNTIME:
        return RoleDecision(role="candidate_runtime", scope="candidate", reason=CANDIDATE_RUNTIME[filename])

    if filename in SOURCE_AVAILABLE_EXTERNAL:
        return RoleDecision(
            role="source_available_external",
            scope="excluded",
            reason=SOURCE_AVAILABLE_EXTERNAL[filename],
        )

    if filename in VENDOR_REPLACEABLE:
        return RoleDecision(role="vendor_replaceable", scope="excluded", reason=VENDOR_REPLACEABLE[filename])

    if filename in EXCLUDED_TOOLS:
        return RoleDecision(role="excluded_tool_or_redistributable", scope="excluded", reason=EXCLUDED_TOOLS[filename])

    if "program files (x86)" in lower_parts and "halo custom edition" in lower_parts:
        return RoleDecision(
            role="unknown_game_directory_pe",
            scope="candidate",
            reason="PE file shipped in the Halo Custom Edition directory without a settled disposition",
        )

    return RoleDecision(role="unknown_pe", scope="candidate", reason="PE file requires explicit catalog disposition")
