"""Build one candidate and its native-realization receipt from checked inputs.

This is the production realization boundary.  It derives link, bridge, loader,
and candidate facts directly from the exact linked payload and does not consume
legacy build-plan, link-receipt, loader-surface, or deployment receipts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..candidate.build_objects import _payload_symbol_rvas
from ..candidate.outcomes import PinnedCodeLayoutAuthorityV2
from ..external.environment import ResolvedExternalEnvironmentV1
from ..pe32.image import parse_pe_image
from ..util import sha256_file


class NativeRealizationBuildError(ValueError):
    """Checked realization inputs cannot produce an exact native candidate."""


def _json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeRealizationBuildError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise NativeRealizationBuildError(f"{context} must be a JSON object")
    return dict(value)


def _resolved_environment_identity(path: Path) -> str:
    """Return the environment contract identity, not its container hash."""

    return ResolvedExternalEnvironmentV1.load(Path(path)).identity


def _linked_payload_facts(
    native_build_manifest: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    manifest_path = Path(native_build_manifest)
    manifest = _json_object(manifest_path, "native build manifest")
    policy = manifest.get("policy")
    if not isinstance(policy, Mapping) or not isinstance(policy.get("image_base"), int):
        raise NativeRealizationBuildError(
            "native build manifest omits its linked image base"
        )
    linker_map = manifest_path.parent / "payload.map"
    symbols = {
        symbol: {"symbol": symbol, "rva": rva}
        for symbol, rva in _payload_symbol_rvas(
            linker_map, image_base=int(policy["image_base"])
        ).items()
    }
    payload = manifest_path.parent / "payload.exe"
    parsed = parse_pe_image(payload)
    try:
        if parsed.machine != "i386" or parsed.bitness != 32:
            raise NativeRealizationBuildError(
                "native realization payload is not IA-32 PE32"
            )
        sections = [
            {
                "index": index,
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "executable": section.executable,
                "writable": section.writable,
            }
            for index, section in enumerate(parsed.sections)
        ]
    finally:
        parsed.pe.close()
    return manifest, symbols, sections


def _checked_native_symbol(
    symbols: Mapping[str, Mapping[str, Any]],
    sections: Sequence[Mapping[str, Any]],
    symbol: str,
    *,
    executable: bool | None,
) -> Mapping[str, Any] | None:
    native = symbols.get(symbol)
    if native is None:
        return None
    rva = native.get("rva")
    containing = [
        section
        for section in sections
        if (
            isinstance(rva, int)
            and int(section["rva_start"]) <= rva < int(section["rva_end"])
        )
    ]
    if (
        len(containing) != 1
        or (
            executable is not None
            and bool(containing[0]["executable"]) is not executable
        )
    ):
        raise NativeRealizationBuildError(
            f"native realization symbol {symbol!r} lacks one compatible section"
        )
    return native


def _bridges(
    ingress: Mapping[str, Any],
    native_symbols: Mapping[str, Mapping[str, Any]],
    linked_sections: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ingresses_by_class: dict[str, list[Mapping[str, Any]]] = {}
    for row in ingress["ingresses"]:
        ingresses_by_class.setdefault(
            str(row["bridge_equivalence_class"]), []
        ).append(row)
    blockers: list[dict[str, Any]] = []
    bridges: list[dict[str, Any]] = []
    for row in ingress["bridges"]:
        bridge_id = str(row["equivalence_class"])
        members = ingresses_by_class.get(bridge_id, [])
        frame_hashes = {
            canonical_sha256_v3(member["physical_frame"]) for member in members
        }
        native = _checked_native_symbol(
            native_symbols,
            linked_sections,
            str(row["symbol"]),
            executable=True,
        )
        if len(frame_hashes) != 1:
            raise NativeRealizationBuildError(
                f"bridge class {bridge_id!r} has no unique physical frame"
            )
        if native is None:
            blockers.append(
                {"code": "bridge_address_unresolved", "bridge_class_id": bridge_id}
            )
            rva = 0
        else:
            rva = int(native["rva"])
        bridges.append(
            {
                "bridge_class_id": bridge_id,
                "native_symbol": str(row["symbol"]),
                "rva": rva,
                "physical_frame_sha256": next(iter(frame_hashes)),
                "capability_ids": sorted(
                    {
                        str(member["capability_id"])
                        for member in members
                        if member["capability_id"] is not None
                    }
                ),
                "ingress_kinds": sorted({str(member["role"]) for member in members}),
            }
        )
    return bridges, blockers


def _loader_surface(candidate_interface: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "entry_rva": candidate_interface["loader"]["entry_rva"],
        "exports_sha256": canonical_sha256_v3(
            candidate_interface["export_directory"]
        ),
        "imports_sha256": canonical_sha256_v3(
            {
                "descriptors": candidate_interface["import_descriptors"],
                "slots": candidate_interface["imports"],
                "delay": candidate_interface["delay_imports"],
            }
        ),
        "tls_sha256": canonical_sha256_v3(candidate_interface["tls"]),
        "base_relocations_sha256": canonical_sha256_v3(
            candidate_interface["base_relocations"]
        ),
        "resources_sha256": (
            None
            if candidate_interface["resources"] is None
            else canonical_sha256_v3(candidate_interface["resources"])
        ),
        "load_config_sha256": (
            None
            if candidate_interface["load_config"] is None
            else canonical_sha256_v3(candidate_interface["load_config"])
        ),
    }


def _pinned_layout_blockers(
    *,
    ingress: Mapping[str, Any],
    original_interface: Mapping[str, Any],
    candidate_interface: Mapping[str, Any],
    resolved_environment_sha256: str,
) -> list[dict[str, Any]]:
    """Join optional numeric-address authority with the actual composed PE."""

    blockers: list[dict[str, Any]] = []
    raw_authorities = ingress.get("pinned_code_layout_authorities", [])
    if not isinstance(raw_authorities, list):
        return [{"code": "pinned_layout_inventory_malformed"}]
    try:
        authorities = {
            authority.authority_id: authority
            for authority in (
                PinnedCodeLayoutAuthorityV2.parse(row)
                for row in raw_authorities
            )
        }
    except (TypeError, ValueError):
        return [{"code": "pinned_layout_inventory_malformed"}]
    if len(authorities) != len(raw_authorities):
        return [{"code": "pinned_layout_identity_duplicate"}]
    protocols = [
        row for row in ingress.get("seh_protocols", [])
        if isinstance(row, Mapping)
        and isinstance(row.get("pinned_layout_authority_id"), str)
    ]
    referenced = {
        str(row["pinned_layout_authority_id"]) for row in protocols
    }
    for authority_id in sorted(set(authorities) - referenced):
        blockers.append({
            "code": "pinned_layout_authority_unreferenced",
            "authority_id": authority_id,
        })
    original_sha256 = original_interface.get("identity", {}).get("pe_sha256")
    original_base = original_interface.get("loader", {}).get("preferred_base")
    candidate_base = candidate_interface.get("loader", {}).get("preferred_base")
    for protocol in protocols:
        authority_id = str(protocol["pinned_layout_authority_id"])
        authority = authorities.get(authority_id)
        if authority is None:
            blockers.append({
                "code": "pinned_layout_authority_missing",
                "authority_id": authority_id,
            })
            continue
        if authority.original_module_sha256 != original_sha256:
            blockers.append({
                "code": "pinned_layout_original_hash_mismatch",
                "authority_id": authority_id,
            })
        if (
            authority.resolved_external_environment_sha256
            != resolved_environment_sha256
        ):
            blockers.append({
                "code": "pinned_layout_environment_mismatch",
                "authority_id": authority_id,
            })
        if (
            original_base != candidate_base
            or authority.required_image_base != original_base
        ):
            blockers.append({
                "code": "pinned_layout_image_base_mismatch",
                "authority_id": authority_id,
                "required": authority.required_image_base,
                "original": original_base,
                "candidate": candidate_base,
            })
        observed = {
            str(value) for value in protocol.get("observed_address_fields", [])
        }
        missing_fields = sorted(observed - set(authority.observed_fields))
        if missing_fields:
            blockers.append({
                "code": "pinned_layout_observed_fields_missing",
                "authority_id": authority_id,
                "fields": missing_fields,
            })
        bound_rvas = {int(row["source_rva"]) for row in authority.rva_bindings}
        required_rvas: set[int] = set()
        if observed & {"ExceptionAddress", "Eip"}:
            required_rvas.update(
                int(portal["source_rva"])
                for portal in protocol.get("portals", [])
                if isinstance(portal, Mapping)
                and isinstance(portal.get("source_rva"), int)
                and not isinstance(portal.get("source_rva"), bool)
            )
        resumption_rva = protocol.get("resumption_rva")
        if (
            "Eip" in observed
            and isinstance(resumption_rva, int)
            and not isinstance(resumption_rva, bool)
        ):
            required_rvas.add(resumption_rva)
        missing_rvas = sorted(required_rvas - bound_rvas)
        if missing_rvas:
            blockers.append({
                "code": "pinned_layout_rva_binding_missing",
                "authority_id": authority_id,
                "rvas": missing_rvas,
            })
    return blockers


def _pinned_layout_requirements(
    *,
    ingress: Mapping[str, Any],
    candidate_sha256: str,
    linker_layout_sha256: str,
) -> list[dict[str, Any]]:
    """Publish validated address premises needed by deployment observation."""

    raw_authorities = ingress.get("pinned_code_layout_authorities", [])
    if not isinstance(raw_authorities, list):
        return []
    try:
        authorities = sorted(
            (PinnedCodeLayoutAuthorityV2.parse(row) for row in raw_authorities),
            key=lambda authority: authority.authority_id,
        )
    except (TypeError, ValueError):
        return []
    return [{
        "authority_id": authority.authority_id,
        "original_module_sha256": authority.original_module_sha256,
        "candidate_module_sha256": candidate_sha256,
        "linker_layout_sha256": linker_layout_sha256,
        "resolved_external_environment_sha256": (
            authority.resolved_external_environment_sha256
        ),
        "required_image_base": authority.required_image_base,
        "rva_bindings": [dict(row) for row in authority.rva_bindings],
        "observed_fields": list(authority.observed_fields),
    } for authority in authorities]
