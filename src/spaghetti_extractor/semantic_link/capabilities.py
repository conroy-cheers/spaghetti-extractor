"""Address-free code and export capabilities owned by semantic linking."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..calls.frame import physical_frame_abi_sha256_v1
from .errors import LinkedSemanticModuleError


def _fail(message: str) -> None:
    raise LinkedSemanticModuleError(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > 2_000_000:
        _fail(f"{context} must be a bounded array")
    return value

def semantic_code_capabilities_v1(
    *, module_interface: Mapping[str, Any],
    effects: Mapping[str, Sequence[Mapping[str, Any]]],
    symbols: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Materialize semantic callback capabilities without native addresses.

    A capability is part of the original module's checked meaning.  Its PE32
    bridge symbol and address are realization details and deliberately do not
    appear here.  Keeping this registry in the linked module lets component
    refinement validate a callback handle without consuming a separately
    scheduled native-ingress plan.
    """

    image_id = module_interface.get("image_id")
    if not isinstance(image_id, str) or not image_id:
        _fail("module interface has no logical image identity")
    symbols_by_rva: dict[int, Mapping[str, Any]] = {}
    for raw in symbols:
        symbol = _mapping(raw, "linked capability target symbol")
        rva = symbol.get("original_rva")
        if (
            symbol.get("kind") == "function"
            and symbol.get("reachable") is True
            and isinstance(rva, int)
            and not isinstance(rva, bool)
        ):
            if rva in symbols_by_rva:
                _fail("reachable code capability target RVA is ambiguous")
            symbols_by_rva[rva] = symbol

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in effects.get("callbacks", ()):
        effect = dict(_mapping(raw, "linked callback capability effect"))
        root_ids = effect.pop("root_ids", None)
        targets = effect.get("targets")
        if targets is None:
            continue
        if (
            not isinstance(root_ids, list)
            or not isinstance(targets, list)
            or targets != sorted(set(targets))
        ):
            _fail("linked callback capability effect is malformed")
        protocol_id = effect.get("protocol_id")
        lifetime = effect.get("lifetime")
        instruction_rva = effect.get("instruction_rva")
        if (
            not isinstance(protocol_id, str) or not protocol_id
            or not isinstance(lifetime, str) or not lifetime
            or not isinstance(instruction_rva, int)
            or isinstance(instruction_rva, bool)
        ):
            _fail("linked callback capability contract is incomplete")
        effect_sha256 = canonical_sha256_v3(effect)
        for target_rva in targets:
            if not isinstance(target_rva, int) or isinstance(target_rva, bool):
                _fail("linked callback capability target is malformed")
            target = symbols_by_rva.get(target_rva)
            if target is None:
                _fail("linked callback capability target is not reachable code")
            capability_id = "code-capability-v1:" + canonical_sha256_v3({
                "module": image_id,
                "escape": effect,
                "target_rva": target_rva,
            })
            if capability_id in seen:
                _fail("linked callback capability identity is duplicated")
            seen.add(capability_id)
            result.append({
                "capability_id": capability_id,
                "logical_image_id": image_id,
                "source_effect_sha256": effect_sha256,
                "source_instruction_rva": instruction_rva,
                "target_rva": target_rva,
                "target_symbol": target["symbol_id"],
                "protocol_id": protocol_id,
                "lifetime": lifetime,
                "root_ids": list(root_ids),
            })
    return sorted(result, key=lambda row: str(row["capability_id"]))

def semantic_export_capabilities_v1(
    *, module_interface: Mapping[str, Any],
    resolved_environment: Mapping[str, Any],
    symbols: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind code exports to checked physical frames without native bridges."""

    image_id = module_interface.get("image_id")
    if not isinstance(image_id, str) or not image_id:
        _fail("module interface has no logical image identity")
    symbols_by_rva = {
        int(row["original_rva"]): row
        for raw in symbols
        for row in [_mapping(raw, "linked export target symbol")]
        if row.get("kind") == "function"
        and row.get("reachable") is True
        and isinstance(row.get("original_rva"), int)
        and not isinstance(row.get("original_rva"), bool)
    }
    checked_exports: dict[str, dict[str, Any]] = {}
    checked_module_exports: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(_rows(
        resolved_environment.get("canonical_boundaries"),
        "resolved canonical boundaries",
    )):
        boundary = _mapping(raw, f"resolved canonical boundary {index}")
        boundary_kind = boundary.get("kind")
        if boundary_kind not in {"checked_protocol", "checked_module_export"}:
            continue
        artifacts = _mapping(
            boundary.get("artifacts"), "resolved boundary artifacts"
        )
        frame_artifact = _mapping(
            artifacts.get("physical_call_frame_v3"),
            "resolved physical-frame artifact",
        )
        frame = _mapping(
            frame_artifact.get("payload"), "resolved physical frame"
        )
        if boundary_kind == "checked_protocol":
            call_artifact = _mapping(
                artifacts.get("checked_call_protocol"),
                "resolved call-protocol artifact",
            )
            call = _mapping(
                call_artifact.get("payload"), "resolved checked call protocol"
            )
            protocol_id = call.get("id")
        else:
            protocol_id = boundary.get("checked_call_protocol_id")
        transport = _mapping(
            frame.get("transport"), "resolved physical transport"
        )
        subject = _mapping(
            transport.get("subject"), "resolved physical subject"
        )
        if subject.get("kind") != "export":
            continue
        subject_id = subject.get("id")
        if (
            not isinstance(subject_id, str) or not subject_id
            or subject.get("image_selector") != image_id
            or not isinstance(frame.get("id"), str)
            or not isinstance(protocol_id, str)
        ):
            _fail("resolved export boundary identity is stale or duplicated")
        checked = {
            "physical_frame": dict(frame),
            "checked_call_protocol_id": protocol_id,
        }
        if boundary_kind == "checked_protocol":
            if subject_id in checked_exports:
                _fail("resolved export boundary identity is stale or duplicated")
            checked_exports[subject_id] = checked
            continue
        target_rva = boundary.get("target_rva")
        if (
            not isinstance(target_rva, int)
            or isinstance(target_rva, bool)
            or target_rva < 0
            or target_rva in checked_module_exports
            or boundary.get("logical_image_id") != image_id
            or boundary.get("physical_abi_sha256")
            != physical_frame_abi_sha256_v1(frame)
        ):
            _fail("resolved module-export boundary is stale or duplicated")
        checked_module_exports[target_rva] = {
            **checked,
            "boundary_subject_id": subject_id,
            "aliases": boundary.get("aliases"),
        }

    directory = _mapping(
        module_interface.get("export_directory"), "module export directory"
    )
    slots = [
        _mapping(raw, "module export slot")
        for raw in _rows(directory.get("slots"), "module export slots")
        if _mapping(raw, "module export slot").get("kind") == "code"
    ]
    slots_by_rva: dict[int, list[Mapping[str, Any]]] = {}
    for slot in slots:
        rva = slot.get("rva")
        if not isinstance(rva, int) or isinstance(rva, bool):
            _fail("code export RVA is malformed")
        slots_by_rva.setdefault(rva, []).append(slot)

    result: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for target_rva, target_slots in sorted(slots_by_rva.items()):
        aliases = sorted((
            {"name": name, "ordinal": int(slot["ordinal"])}
            for slot in target_slots
            for name in (
                list(slot.get("names", ()))
                if slot.get("names") else [None]
            )
        ), key=lambda row: (
            int(row["ordinal"]), "" if row["name"] is None else str(row["name"])
        ))
        subject_ids = {
            *(str(row["name"]) for row in aliases if row["name"] is not None),
            *(f"ordinal:{row['ordinal']}" for row in aliases),
        }
        matches = [
            (subject_id, checked_exports[subject_id])
            for subject_id in sorted(subject_ids)
            if subject_id in checked_exports
        ]
        target = symbols_by_rva.get(target_rva)
        module_export = checked_module_exports.get(target_rva)
        if module_export is not None:
            if module_export.get("aliases") != aliases or matches:
                _fail(
                    "resolved module-export aliases disagree with the EAT or "
                    "duplicate authored export authority"
                )
            selected_subject = str(module_export["boundary_subject_id"])
            checked = module_export
        elif len(matches) == 1:
            selected_subject, checked = matches[0]
        else:
            selected_subject = ""
            checked = None
        if checked is None or target is None:
            blockers.append({
                "code": "linked_export_call_protocol_missing_or_ambiguous",
                "logical_image_id": image_id,
                "target_rva": target_rva,
                "aliases": aliases,
                "matching_subject_ids": [row[0] for row in matches],
            })
            continue
        frame = _mapping(
            checked["physical_frame"], "linked export physical frame"
        )
        core = {
            "logical_image_id": image_id,
            "target_rva": target_rva,
            "target_symbol": target["symbol_id"],
            "exports": aliases,
            "boundary_subject_id": selected_subject,
            "checked_call_protocol_id": checked["checked_call_protocol_id"],
            "physical_frame_id": frame["id"],
            "physical_frame": dict(frame),
            "root_ids": list(target.get("root_ids", ())),
        }
        result.append({
            "capability_id": "export-capability-v1:" + canonical_sha256_v3(core),
            **core,
        })
    return (
        sorted(result, key=lambda row: str(row["capability_id"])),
        blockers,
    )
