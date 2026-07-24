"""Bind Stage B runtime-call obligations to native engine call sites.

This artifact is an inventory and consistency check only.  It deliberately
does not confer acceptance authority on a generated native candidate.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .errors import StageAInputError
from .stage_b_native_engine import NATIVE_ENGINE_PLAN_FORMAT
from .util import json_dumps, sha256_file, sha256_text, write_json


NATIVE_RUNTIME_BINDING_FORMAT = "stage-b-native-runtime-binding-v1"
RUNTIME_CALL_OBLIGATIONS_FORMAT = "stage-b-runtime-call-obligations-v1"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_HEX_BYTES_RE = re.compile(r"(?:[0-9a-f]{2})+")
_NATIVE_KINDS = frozenset({"external_call", "indirect_call"})
_OUTSIDE_SCOPE_KINDS = frozenset({"internal_call", "rep_movsd"})
_BOUNDARY_KINDS = _NATIVE_KINDS | _OUTSIDE_SCOPE_KINDS
_BOUNDARY_STATUSES = frozenset({"bound", "unbound"})
_PLAN_STATUSES = frozenset({"ready", "incomplete"})
_OBLIGATION_STATUSES = frozenset({"complete", "incomplete"})

_Selector = tuple[str, int, int]


def build_stage_b_native_runtime_binding(
    *,
    native_engine_plan: Path,
    runtime_call_obligations: Path,
) -> dict[str, Any]:
    """Build a deterministic, fail-closed native runtime binding inventory."""

    plan_path = Path(native_engine_plan)
    obligations_path = Path(runtime_call_obligations)
    plan = _read_json_object(plan_path, "native engine plan")
    obligations = _read_json_object(
        obligations_path, "runtime-call obligations"
    )
    parsed_plan = _validate_native_engine_plan(plan)
    parsed_obligations = _validate_runtime_call_obligations(obligations)

    plan_state_sha256 = parsed_plan["state_machine_sha256"]
    obligation_state_sha256 = parsed_obligations["state_machine_sha256"]
    if plan_state_sha256 != obligation_state_sha256:
        raise StageAInputError(
            "native engine plan and runtime-call obligations bind different "
            "source state-machine SHA-256 digests"
        )

    plan_sites: list[dict[str, Any]] = parsed_plan["sites"]
    boundaries: list[dict[str, Any]] = parsed_obligations["boundaries"]
    sites_by_selector = {site["selector"]: site for site in plan_sites}
    native_obligations = sorted(
        (
            boundary
            for boundary in boundaries
            if boundary["kind"] in _NATIVE_KINDS
            and boundary["status"] == "unbound"
        ),
        key=_boundary_sort_key,
    )
    outside_boundaries = sorted(
        (boundary for boundary in boundaries if boundary not in native_obligations),
        key=_boundary_sort_key,
    )

    blockers: list[dict[str, Any]] = []
    if parsed_plan["status"] == "incomplete":
        for source_blocker in parsed_plan["blockers"]:
            blockers.append(_blocker(
                "native_engine_plan_blocker",
                "the native engine plan still has a hard generation blocker",
                source_blocker["next_action"],
                source_category=source_blocker["category"],
                source_blocker=source_blocker,
            ))
    if parsed_obligations["status"] == "incomplete":
        blockers.append(_blocker(
            "runtime_call_inventory_incomplete",
            "the runtime-call obligation source does not claim a complete inventory",
            "regenerate the runtime-call obligations from a nonempty, canonical "
            "Stage B state machine",
        ))

    bound_sites: list[dict[str, Any]] = []
    consumed_selectors: set[_Selector] = set()
    for obligation in native_obligations:
        selector = obligation["selector"]
        site = sites_by_selector.get(selector)
        if site is None:
            blockers.append(_selector_blocker(
                "native_site_missing",
                "an unbound runtime-call obligation has no exact native site",
                "regenerate the native engine plan from the same state machine "
                "and include this exact call boundary",
                obligation,
            ))
            continue
        consumed_selectors.add(selector)
        mismatch = _binding_mismatch(obligation, site)
        if mismatch is not None:
            blockers.append(mismatch)
            continue
        bound_sites.append(_bound_site_payload(obligation, site))

    for site in sorted(plan_sites, key=_site_sort_key):
        if site["selector"] in consumed_selectors:
            continue
        blockers.append(_selector_blocker(
            "unexpected_native_site",
            "the native engine plan contains a site with no unbound runtime-call obligation",
            "remove the extra native bridge or regenerate both artifacts from "
            "the same unbound boundary inventory",
            site,
            plan_site_id=site["plan_site_id"],
        ))

    outside_scope = [
        _outside_scope_payload(boundary) for boundary in outside_boundaries
    ]
    for boundary in outside_boundaries:
        if boundary["kind"] in _NATIVE_KINDS:
            blockers.append(_selector_blocker(
                "native_boundary_already_bound",
                "a native-call boundary already claims a different runtime binding",
                "choose one runtime owner and regenerate the native engine plan "
                "without a competing bridge",
                boundary,
                obligation_status=boundary["status"],
            ))
        elif boundary["status"] != "bound":
            blockers.append(_selector_blocker(
                "outside_scope_boundary_unbound",
                "a runtime boundary outside native-call scope remains unbound",
                "bind the boundary with its semantic runtime owner before "
                "treating the candidate as ready",
                boundary,
                kind=boundary["kind"],
            ))

    blockers.sort(key=_blocker_sort_key)
    bound_sites.sort(key=_site_sort_key)
    outside_scope.sort(key=_site_sort_key)
    result = {
        "format": NATIVE_RUNTIME_BINDING_FORMAT,
        "status": "ready" if not blockers else "incomplete",
        "acceptance_authority": False,
        "sources": {
            "state_machine": {"sha256": plan_state_sha256},
            "native_engine_plan": {
                "path": plan_path.name,
                "sha256": sha256_file(plan_path),
            },
            "runtime_call_obligations": {
                "path": obligations_path.name,
                "sha256": sha256_file(obligations_path),
            },
        },
        "counts": {
            "call_boundaries": len(boundaries),
            "native_obligations": len(native_obligations),
            "native_sites": len(plan_sites),
            "bound_native_sites": len(bound_sites),
            "unbound_native_obligations": len(native_obligations) - len(bound_sites),
            "outside_scope": len(outside_scope),
            "blockers": len(blockers),
        },
        "sites": bound_sites,
        "outside_scope": outside_scope,
        "blockers": blockers,
        "authority": (
            "candidate runtime binding inventory only; final acceptance requires "
            "the Stage A whole-program proof"
        ),
    }
    return result


def write_stage_b_native_runtime_binding(
    *,
    native_engine_plan: Path,
    runtime_call_obligations: Path,
    out: Path,
) -> dict[str, Any]:
    """Build and canonically write a native runtime binding artifact."""

    result = build_stage_b_native_runtime_binding(
        native_engine_plan=native_engine_plan,
        runtime_call_obligations=runtime_call_obligations,
    )
    write_json(Path(out), result)
    return result


def bind_stage_b_native_runtime_obligations(
    *,
    native_engine_plan: Path,
    runtime_call_obligations: Path,
    out: Path | None = None,
) -> dict[str, Any]:
    """Compatibility entry point for building or writing the binding."""

    if out is None:
        return build_stage_b_native_runtime_binding(
            native_engine_plan=native_engine_plan,
            runtime_call_obligations=runtime_call_obligations,
        )
    return write_stage_b_native_runtime_binding(
        native_engine_plan=native_engine_plan,
        runtime_call_obligations=runtime_call_obligations,
        out=out,
    )


def bind_stage_b_native_runtime(
    *,
    native_engine_plan: Path,
    runtime_call_obligations: Path,
) -> dict[str, Any]:
    """Short alias for callers that do not need to write the artifact."""

    return build_stage_b_native_runtime_binding(
        native_engine_plan=native_engine_plan,
        runtime_call_obligations=runtime_call_obligations,
    )


def _validate_native_engine_plan(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("format") != NATIVE_ENGINE_PLAN_FORMAT:
        raise StageAInputError(
            f"native engine plan format must be {NATIVE_ENGINE_PLAN_FORMAT}"
        )
    status = payload.get("status")
    if status not in _PLAN_STATUSES:
        raise StageAInputError("native engine plan status must be ready or incomplete")
    state_machine_sha256 = _required_sha256(
        payload.get("state_machine_sha256"),
        "native engine plan state_machine_sha256",
    )
    raw_sites = _required_list(payload.get("external_sites"), "native engine plan external_sites")
    sites = [
        _parse_native_site(item, index)
        for index, item in enumerate(raw_sites)
    ]
    raw_blockers = _required_list(payload.get("blockers"), "native engine plan blockers")
    blockers = [
        _parse_plan_blocker(item, index)
        for index, item in enumerate(raw_blockers)
    ]
    callbacks = _required_list(
        payload.get("callback_targets"), "native engine plan callback_targets"
    )
    callback_targets = [
        _required_u32(value, f"native engine plan callback target {index}")
        for index, value in enumerate(callbacks)
    ]
    if len(set(callback_targets)) != len(callback_targets):
        raise StageAInputError("native engine plan has duplicate callback targets")

    counts = _required_object(payload.get("counts"), "native engine plan counts")
    expected_count_fields = {
        "transfers", "external_sites", "indirect_calls", "callback_targets", "blockers"
    }
    if set(counts) != expected_count_fields:
        raise StageAInputError("native engine plan counts have schema drift")
    for field in expected_count_fields:
        _required_count(counts.get(field), f"native engine plan counts.{field}")
    expected_counts = {
        "external_sites": len(sites),
        "indirect_calls": sum(site["site_kind"] == "dynamic_target" for site in sites),
        "callback_targets": len(callback_targets),
        "blockers": len(blockers),
    }
    for field, expected in expected_counts.items():
        if counts[field] != expected:
            raise StageAInputError(
                f"native engine plan counts.{field} does not match its inventory"
            )
    if (status == "ready") != (not blockers):
        raise StageAInputError(
            "native engine plan status does not match its blocker inventory"
        )
    _reject_duplicate_sites(sites)
    return {
        "status": status,
        "state_machine_sha256": state_machine_sha256,
        "sites": sites,
        "blockers": blockers,
    }


def _validate_runtime_call_obligations(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("format") != RUNTIME_CALL_OBLIGATIONS_FORMAT:
        raise StageAInputError(
            "runtime-call obligations format must be "
            f"{RUNTIME_CALL_OBLIGATIONS_FORMAT}"
        )
    status = payload.get("status")
    if status not in _OBLIGATION_STATUSES:
        raise StageAInputError(
            "runtime-call obligations status must be complete or incomplete"
        )
    if payload.get("authority") != "stage-a-semantic-transfer-contracts":
        raise StageAInputError("runtime-call obligations authority is malformed")
    state_machine = _required_object(
        payload.get("state_machine"), "runtime-call obligations state_machine"
    )
    _required_string(
        state_machine.get("path"), "runtime-call obligations state_machine.path"
    )
    state_machine_sha256 = _required_sha256(
        state_machine.get("sha256"),
        "runtime-call obligations state_machine.sha256",
    )
    raw_boundaries = _required_list(
        payload.get("call_boundaries"), "runtime-call obligations call_boundaries"
    )
    boundaries = [
        _parse_call_boundary(item, index)
        for index, item in enumerate(raw_boundaries)
    ]
    _reject_duplicate_boundaries(boundaries)
    _validate_obligation_counts(payload.get("counts"), boundaries)
    return {
        "status": status,
        "state_machine_sha256": state_machine_sha256,
        "boundaries": boundaries,
    }


def _parse_native_site(value: Any, index: int) -> dict[str, Any]:
    site = _required_object(value, f"native engine site {index}")
    plan_site_id = _required_count(site.get("id"), f"native engine site {index} id")
    transfer_id = _required_string(
        site.get("transfer_id"), f"native engine site {index} transfer_id"
    )
    event_index = _required_count(
        site.get("event_index"), f"native engine site {index} event_index"
    )
    instruction_rva = _required_u32(
        site.get("instruction_rva"), f"native engine site {index} instruction_rva"
    )
    return_rva = _required_u32(
        site.get("return_rva"), f"native engine site {index} return_rva"
    )
    instruction_bytes = site.get("instruction_bytes")
    if not isinstance(instruction_bytes, str) or not _HEX_BYTES_RE.fullmatch(instruction_bytes):
        raise StageAInputError(
            f"native engine site {index} instruction_bytes must be lowercase hexadecimal bytes"
        )
    disposition = site.get("disposition")
    if disposition not in {"returns_here", "tail_jump"}:
        raise StageAInputError(
            f"native engine site {index} disposition is malformed"
        )
    site_kind = site.get("site_kind")
    if site_kind not in {"direct_import", "dynamic_target"}:
        raise StageAInputError(f"native engine site {index} site_kind is malformed")
    if site_kind == "direct_import":
        import_identity = _parse_import_identity(
            site.get("import"), f"native engine site {index} import"
        )
    else:
        if site.get("import") is not None:
            raise StageAInputError(
                f"native engine dynamic-target site {index} must not name an import"
            )
        import_identity = None
    return {
        "selector": (transfer_id, event_index, instruction_rva),
        "plan_site_id": plan_site_id,
        "transfer_id": transfer_id,
        "event_index": event_index,
        "instruction_rva": instruction_rva,
        "return_rva": return_rva,
        "instruction_bytes": instruction_bytes,
        "disposition": disposition,
        "site_kind": site_kind,
        "import": import_identity,
    }


def _parse_call_boundary(value: Any, index: int) -> dict[str, Any]:
    boundary = _required_object(value, f"runtime-call boundary {index}")
    transfer_id = _required_string(
        boundary.get("transfer_id"), f"runtime-call boundary {index} transfer_id"
    )
    event_index = _required_count(
        boundary.get("event_index"), f"runtime-call boundary {index} event_index"
    )
    instruction_rva = _required_u32(
        boundary.get("instruction_rva"),
        f"runtime-call boundary {index} instruction_rva",
    )
    obligation_id = _required_string(
        boundary.get("id"), f"runtime-call boundary {index} id"
    )
    expected_id = f"runtime-call:{transfer_id}:{event_index}"
    if obligation_id != expected_id:
        raise StageAInputError(
            f"runtime-call boundary {index} id does not match its transfer and event index"
        )
    status = boundary.get("status")
    if status not in _BOUNDARY_STATUSES:
        raise StageAInputError(f"runtime-call boundary {index} status is malformed")
    kind = boundary.get("kind")
    if kind not in _BOUNDARY_KINDS:
        raise StageAInputError(f"runtime-call boundary {index} kind is unsupported")
    binding = boundary.get("binding")
    if status == "bound":
        binding = _required_string(binding, f"runtime-call boundary {index} binding")
    elif binding is not None:
        raise StageAInputError(
            f"unbound runtime-call boundary {index} must not claim a binding"
        )
    parsed: dict[str, Any] = {
        "selector": (transfer_id, event_index, instruction_rva),
        "obligation_id": obligation_id,
        "status": status,
        "binding": binding,
        "transfer_id": transfer_id,
        "event_index": event_index,
        "instruction_rva": instruction_rva,
        "contract_sha256": _required_sha256(
            boundary.get("contract_sha256"),
            f"runtime-call boundary {index} contract_sha256",
        ),
        "rva_start": _required_u32(
            boundary.get("rva_start"), f"runtime-call boundary {index} rva_start"
        ),
        "kind": kind,
    }
    if kind == "external_call":
        parsed["identity"] = _parse_import_identity(
            boundary.get("identity"), f"runtime-call boundary {index} identity"
        )
    elif kind == "internal_call":
        parsed["target_rva"] = _required_u32(
            boundary.get("target_rva"),
            f"runtime-call boundary {index} target_rva",
        )
    elif kind == "indirect_call":
        parsed["target"] = boundary.get("target")
    return parsed


def _parse_import_identity(value: Any, field: str) -> dict[str, Any]:
    identity = _required_object(value, field)
    if set(identity) != {"dll", "symbol", "ordinal"}:
        raise StageAInputError(f"{field} has schema drift")
    dll = _required_string(identity.get("dll"), f"{field}.dll").lower()
    symbol = identity.get("symbol")
    ordinal = identity.get("ordinal")
    has_symbol = isinstance(symbol, str) and bool(symbol)
    has_ordinal = (
        isinstance(ordinal, int)
        and not isinstance(ordinal, bool)
        and 0 <= ordinal < 2**32
    )
    if has_symbol == has_ordinal:
        raise StageAInputError(f"{field} must name exactly one symbol or ordinal")
    if symbol is not None and not has_symbol:
        raise StageAInputError(f"{field}.symbol is malformed")
    if ordinal is not None and not has_ordinal:
        raise StageAInputError(f"{field}.ordinal is malformed")
    return {
        "dll": dll,
        "symbol": symbol if has_symbol else None,
        "ordinal": ordinal if has_ordinal else None,
    }


def _parse_plan_blocker(value: Any, index: int) -> dict[str, Any]:
    blocker = _required_object(value, f"native engine blocker {index}")
    _required_string(blocker.get("category"), f"native engine blocker {index} category")
    if blocker.get("severity") != "hard":
        raise StageAInputError(
            f"native engine blocker {index} severity must be hard"
        )
    _required_string(
        blocker.get("next_action"), f"native engine blocker {index} next_action"
    )
    return dict(blocker)


def _reject_duplicate_sites(sites: list[dict[str, Any]]) -> None:
    seen_ids: set[int] = set()
    seen_selectors: set[_Selector] = set()
    seen_rvas: set[int] = set()
    for site in sites:
        if site["plan_site_id"] in seen_ids:
            raise StageAInputError("native engine plan has duplicate site ids")
        if site["selector"] in seen_selectors:
            raise StageAInputError("native engine plan has duplicate native site selectors")
        if site["instruction_rva"] in seen_rvas:
            raise StageAInputError("native engine plan has duplicate native instruction RVAs")
        seen_ids.add(site["plan_site_id"])
        seen_selectors.add(site["selector"])
        seen_rvas.add(site["instruction_rva"])


def _reject_duplicate_boundaries(boundaries: list[dict[str, Any]]) -> None:
    seen_ids: set[str] = set()
    seen_selectors: set[_Selector] = set()
    for boundary in boundaries:
        if boundary["obligation_id"] in seen_ids:
            raise StageAInputError("runtime-call obligations contain duplicate ids")
        if boundary["selector"] in seen_selectors:
            raise StageAInputError(
                "runtime-call obligations contain duplicate boundary selectors"
            )
        seen_ids.add(boundary["obligation_id"])
        seen_selectors.add(boundary["selector"])


def _validate_obligation_counts(
    value: Any, boundaries: list[dict[str, Any]]
) -> None:
    counts = _required_object(value, "runtime-call obligations counts")
    expected_fields = {
        "call_boundaries", "unbound_obligations", "by_status", "unbound_by_kind"
    }
    if set(counts) != expected_fields:
        raise StageAInputError("runtime-call obligations counts have schema drift")
    expected_statuses = dict(sorted(Counter(
        boundary["status"] for boundary in boundaries
    ).items()))
    expected_unbound_kinds = dict(sorted(Counter(
        boundary["kind"]
        for boundary in boundaries
        if boundary["status"] == "unbound"
    ).items()))
    expected = {
        "call_boundaries": len(boundaries),
        "unbound_obligations": sum(
            boundary["status"] == "unbound" for boundary in boundaries
        ),
        "by_status": expected_statuses,
        "unbound_by_kind": expected_unbound_kinds,
    }
    if counts != expected:
        raise StageAInputError(
            "runtime-call obligations counts do not match the boundary inventory"
        )


def _binding_mismatch(
    obligation: dict[str, Any], site: dict[str, Any]
) -> dict[str, Any] | None:
    if obligation["kind"] == "external_call":
        if site["site_kind"] != "direct_import":
            return _selector_blocker(
                "native_site_kind_mismatch",
                "a direct import obligation is not bound to a direct-import native site",
                "regenerate the native site as direct_import for this exact boundary",
                obligation,
                expected="direct_import",
                observed=site["site_kind"],
            )
        if site["import"] != obligation["identity"]:
            return _selector_blocker(
                "direct_import_identity_mismatch",
                "the native site import identity differs from the runtime obligation",
                "regenerate the bridge for the exact DLL and symbol or ordinal identity",
                obligation,
                expected=obligation["identity"],
                observed=site["import"],
            )
    elif site["site_kind"] != "dynamic_target":
        return _selector_blocker(
            "native_site_kind_mismatch",
            "an indirect-call obligation is not bound to a dynamic-target native site",
            "regenerate the native site as dynamic_target for this exact boundary",
            obligation,
            expected="dynamic_target",
            observed=site["site_kind"],
        )
    return None


def _bound_site_payload(
    obligation: dict[str, Any], site: dict[str, Any]
) -> dict[str, Any]:
    payload = {
        "id": _deterministic_id("native-runtime-site", obligation["selector"]),
        "status": "bound",
        "obligation_id": obligation["obligation_id"],
        "plan_site_id": site["plan_site_id"],
        "transfer_id": obligation["transfer_id"],
        "event_index": obligation["event_index"],
        "instruction_rva": obligation["instruction_rva"],
        "contract_sha256": obligation["contract_sha256"],
        "kind": obligation["kind"],
        "site_kind": site["site_kind"],
        "return_rva": site["return_rva"],
        "instruction_bytes": site["instruction_bytes"],
        "disposition": site["disposition"],
        "import": site["import"],
    }
    return payload


def _outside_scope_payload(boundary: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "id": _deterministic_id("native-runtime-outside", boundary["selector"]),
        "obligation_id": boundary["obligation_id"],
        "status": boundary["status"],
        "binding": boundary["binding"],
        "transfer_id": boundary["transfer_id"],
        "event_index": boundary["event_index"],
        "instruction_rva": boundary["instruction_rva"],
        "contract_sha256": boundary["contract_sha256"],
        "kind": boundary["kind"],
        "reason": (
            "already_bound_semantic_runtime_event"
            if boundary["status"] == "bound"
            and boundary["kind"] in _OUTSIDE_SCOPE_KINDS
            else "not_an_unbound_native_call_obligation"
        ),
    }
    if "target_rva" in boundary:
        payload["target_rva"] = boundary["target_rva"]
    return payload


def _selector_blocker(
    category: str,
    message: str,
    next_action: str,
    item: dict[str, Any],
    **fields: Any,
) -> dict[str, Any]:
    return _blocker(
        category,
        message,
        next_action,
        transfer_id=item["transfer_id"],
        event_index=item["event_index"],
        instruction_rva=item["instruction_rva"],
        **fields,
    )


def _blocker(
    category: str,
    message: str,
    next_action: str,
    **fields: Any,
) -> dict[str, Any]:
    return {
        "category": category,
        "severity": "hard",
        "message": message,
        "next_action": next_action,
        **fields,
    }


def _deterministic_id(prefix: str, selector: _Selector) -> str:
    digest = sha256_text(json_dumps({
        "transfer_id": selector[0],
        "event_index": selector[1],
        "instruction_rva": selector[2],
    }))
    return f"{prefix}:{digest}"


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StageAInputError(f"cannot read {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise StageAInputError(f"{label} must be a JSON object")
    return value


def _required_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageAInputError(f"{field} must be an object")
    return value


def _required_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{field} must be a list")
    return value


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{field} must be a non-empty string")
    return value


def _required_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise StageAInputError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _required_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageAInputError(f"{field} must be a nonnegative integer")
    return value


def _required_u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageAInputError(f"{field} must be a 32-bit unsigned integer")
    return value


def _boundary_sort_key(item: dict[str, Any]) -> tuple[str, int, int]:
    return item["selector"]


def _site_sort_key(item: dict[str, Any]) -> tuple[str, int, int]:
    if "selector" in item:
        return item["selector"]
    return (item["transfer_id"], item["event_index"], item["instruction_rva"])


def _blocker_sort_key(item: dict[str, Any]) -> str:
    return json_dumps(item)


__all__ = [
    "NATIVE_RUNTIME_BINDING_FORMAT",
    "RUNTIME_CALL_OBLIGATIONS_FORMAT",
    "bind_stage_b_native_runtime",
    "bind_stage_b_native_runtime_obligations",
    "build_stage_b_native_runtime_binding",
    "write_stage_b_native_runtime_binding",
]
