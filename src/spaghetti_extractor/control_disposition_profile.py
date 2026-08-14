"""Project profile graphs onto the import facts needed by control extraction.

Exact machine-IR extraction must not depend on argument, memory, resource, or
callback contracts.  It needs only the imports that provably do not return so
rooted direct control does not follow an impossible continuation.  This module
builds that compact projection from the fully validated profile graph.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from .authority.external_abi import CONTROL_DISPOSITION_PROFILE_ID
from .machine_import_profiles import load_machine_import_profile_set


CONTROL_DISPOSITION_PROFILE_FORMAT = "stage-a-static-machine-import-profile-v1"
def build_control_disposition_profile(
    profile_paths: Sequence[Path | str],
) -> dict[str, Any]:
    """Return a canonical profile containing only fixed-arity no-return calls.

    The result deliberately contains no source paths, profile hashes, entry
    indices, or non-control effects.  Consequently an unrelated ABI/profile
    edit has exactly the same projection and cannot invalidate exact machine
    semantics downstream.
    """

    selected = load_machine_import_profile_set(profile_paths)
    entries: list[dict[str, Any]] = []
    for contract in selected.contracts:
        payload = contract.contract
        if (
            payload.get("disposition") != "terminates"
            or contract.arity_kind != "fixed"
            or contract.argument_words is None
        ):
            continue
        abi_template = payload.get("abi_template")
        if abi_template not in {"pe32-cdecl-v1", "pe32-stdcall-v1"}:
            continue
        imported: dict[str, Any] = {"dll": contract.identity.dll}
        imported[contract.identity.kind] = contract.identity.value
        rendered_target = (
            str(contract.identity.value)
            if contract.identity.kind == "symbol"
            else f"ordinal-{contract.identity.value}"
        )
        entries.append({
            "id": (
                "control-disposition:"
                f"{contract.identity.dll}!{rendered_target}"
            ),
            "import": imported,
            "abi_template": abi_template,
            "argument_words": contract.argument_words,
            "disposition": "terminates",
        })
    entries.sort(
        key=lambda row: (
            str(row["import"]["dll"]),
            "symbol" if "symbol" in row["import"] else "ordinal",
            str(row["import"].get("symbol", row["import"].get("ordinal"))),
        )
    )
    return {
        "format": CONTROL_DISPOSITION_PROFILE_FORMAT,
        "id": CONTROL_DISPOSITION_PROFILE_ID,
        "default_callback_effect": "none",
        "machine_import_signatures": entries,
    }


__all__ = [
    "CONTROL_DISPOSITION_PROFILE_FORMAT",
    "CONTROL_DISPOSITION_PROFILE_ID",
    "build_control_disposition_profile",
]
