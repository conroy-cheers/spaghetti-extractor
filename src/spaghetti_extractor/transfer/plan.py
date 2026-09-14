"""Compile, serialize, and strictly validate executable-transfer-plan-v2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    MACHINE_IR_FORMAT,
    SEMANTIC_IR_FORMAT,
    SEMANTIC_TRANSFER_CONTRACT_FORMAT,
)
from .x87 import typed_x87_operation_from_payload
from ..machine_ir.memory_actions import (
    MemoryActionError,
    validate_memory_action_graph,
)
from ..machine_ir.definedness import analyze_definedness_rows
from ..machine_ir.schema import RAW_INSTRUCTION_FIELDS
from ..util import sha256_file, write_json
from .compiler import _TransferCompiler
from .definedness import analyze_transfer_definedness_v2
from .finite_control import _finite_control_routes, _validate_finite_control_routes
from .formats import EXECUTABLE_TRANSFER_PLAN_FORMAT
from .model import (
    _FLAGS,
    _REGISTERS,
    TransferPlanError,
    _Action,
    _Call,
    _ExceptionOccurrence,
    _Node,
    _Transfer,
    _TypedX87Program,
)
from .operations import (
    NATIVE_EXCEPTION_EFFECTS_V2,
    action_operation_v2,
    expression_operation_v2,
    native_exception_operations_for_call_v2,
    operation_registry_payload_v2,
    runtime_provider_requirements_v2,
)
from .values import (
    _list,
    _nonnegative,
    _object,
    _read_jsonl,
    _sha256,
    _string,
    _u32,
)

def adapt_exact_machine_ir_rows(
    units: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project byte-free exact machine IR into the checked transfer compiler."""

    rows: list[dict[str, Any]] = []
    for index, unit in enumerate(units):
        if unit.get("format") != MACHINE_IR_FORMAT or unit.get("record_kind") != "unit":
            raise TransferPlanError(
                f"machine-IR record {index} is not a v3 unit",
                code="malformed_machine_ir_input",
            )
        if _contains_raw_instruction_material(unit):
            raise TransferPlanError(
                f"machine-IR record {index} contains raw instruction material",
                code="malformed_machine_ir_input",
            )
        identity = _string(unit.get("id"), "machine-IR unit id")
        source = _object(unit.get("source"), f"{identity} source binding")
        original = _object(source.get("original"), f"{identity} source span")
        semantics = _object(unit.get("semantics"), f"{identity} semantics")
        memory_actions = _object(
            semantics.get("memory_actions"), f"{identity} memory actions"
        )
        try:
            validate_memory_action_graph(memory_actions, require_authoritative=True)
        except MemoryActionError as exc:
            raise TransferPlanError(
                f"{identity}: memory action graph is not authoritative: {exc}",
                code="malformed_memory_action_graph",
            ) from exc
        source_digest = _sha256(
            source.get("instruction_bytes_sha256"),
            f"{identity} source span SHA-256",
        )
        rva_start = _u32(original.get("rva_start"), "machine-IR start RVA")
        rva_end = _u32(original.get("rva_end"), "machine-IR end RVA")
        span_size = _nonnegative(original.get("size"), "machine-IR span size")
        if rva_end <= rva_start or span_size != rva_end - rva_start:
            raise TransferPlanError(
                f"{identity}: machine-IR source span is inconsistent",
                code="malformed_machine_ir_input",
            )
        row: dict[str, Any] = {
            "format": SEMANTIC_TRANSFER_CONTRACT_FORMAT,
            "expression_model": SEMANTIC_IR_FORMAT,
            "id": identity,
            "status": (
                "reimplementable"
                if unit.get("status") == "qualified"
                else "incomplete"
            ),
            "reachable": unit.get("reachable") is True,
            "contract_sha256": _sha256(
                source.get("contract_sha256"),
                f"{identity} contract SHA-256",
            ),
            "instruction_bytes_sha256": source_digest,
            "original": {
                "rva_start": rva_start,
                "rva_end": rva_end,
                "size": span_size,
            },
            "_machine_ir_x87_micro_ops": _list(
                unit.get("x87_micro_ops"), f"{identity} x87 micro-ops"
            ),
            "instructions": _list(
                unit.get("instructions", []), f"{identity} instructions"
            ),
            "memory_actions": memory_actions,
        }
        for field in (
            "pre_state", "register_writes", "flag_writes", "memory_events",
            "external_events", "faults", "ordered_events", "edge_conditions",
            "outcome", "stack_delta", "counts", "fpu_state",
            "instruction_effect_schedule",
        ):
            row[field] = semantics.get(field)
        rows.append(row)
    return rows


def compile_transfer_rows(
    rows: list[dict[str, Any]],
    *,
    collect_blockers: bool,
) -> tuple[tuple[_Transfer, ...], list[dict[str, Any]]]:
    transfers: list[_Transfer] = []
    blockers: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_rvas: set[int] = set()
    for index, row in enumerate(rows):
        if row.get("status") == "incomplete":
            error = TransferPlanError(
                f"{row.get('id')}: semantic transfer is not qualified",
                code="machine_ir_semantics_incomplete",
                next_action=(
                    "classify the bytes as non-code or implement and qualify their semantics"
                ),
            )
            if not collect_blockers:
                raise error
            blockers.append(_blocker(row, index, error, "semantic_qualification"))
            continue
        try:
            transfer = _TransferCompiler(row).compile()
        except TransferPlanError as exc:
            if not collect_blockers:
                raise
            blockers.append(_blocker(row, index, exc, "semantic_lowering"))
            continue
        if transfer.identity in seen_ids or transfer.rva_start in seen_rvas:
            code = (
                "duplicate_transfer_id"
                if transfer.identity in seen_ids
                else "duplicate_transfer_rva"
            )
            error = TransferPlanError(
                f"duplicate transfer RVA 0x{transfer.rva_start:x}",
                code=code,
                next_action="split or reconcile duplicate exact transfers",
            )
            if not collect_blockers:
                raise error
            blockers.append(_blocker(row, index, error, "identity_validation"))
            continue
        seen_ids.add(transfer.identity)
        seen_rvas.add(transfer.rva_start)
        transfers.append(transfer)
    blockers.sort(key=transfer_blocker_sort_key)
    return tuple(sorted(transfers, key=lambda item: item.rva_start)), blockers


def compile_exact_machine_ir(
    machine_ir: Path,
    *,
    collect_blockers: bool = False,
) -> tuple[tuple[_Transfer, ...], list[dict[str, Any]]]:
    return compile_transfer_rows(
        adapt_exact_machine_ir_rows(_read_jsonl(Path(machine_ir))),
        collect_blockers=collect_blockers,
    )


def write_executable_transfer_plan(
    *,
    machine_ir: Path,
    machine_ir_manifest: Path,
    out: Path,
) -> dict[str, Any]:
    """Compile one exact machine universe into the sole renderer input."""

    machine_ir = Path(machine_ir)
    manifest_path = Path(machine_ir_manifest)
    units = _read_jsonl(machine_ir)
    manifest = _load_json(manifest_path, "machine-IR manifest")
    machine_sha = sha256_file(machine_ir)
    _validate_manifest(manifest, units, machine_sha)
    semantic_rows = adapt_exact_machine_ir_rows(units)
    transfers, blockers = compile_transfer_rows(
        semantic_rows, collect_blockers=True
    )
    source_definedness = analyze_definedness_rows(
        [_sanitize_source_bindings(row) for row in semantic_rows]
    )
    inventory = [_unit_binding(unit) for unit in units]
    unit_inventory_sha = canonical_sha256_v3(inventory)
    exact_universe_sha = canonical_sha256_v3({
        "pe_sha256": manifest["binary"]["sha256"],
        "units": [
            {
                "id": row["unit_id"],
                "unit_ir_sha256": row["unit_ir_sha256"],
            }
            for row in sorted(inventory, key=lambda item: item["unit_id"])
        ],
    })
    inventory_by_id = {str(row["unit_id"]): row for row in inventory}
    transfer_rows = [
        _transfer_payload(row, inventory_by_id[row.identity]) for row in transfers
    ]
    finite_control_routes = _finite_control_routes(
        manifest,
        binary=_object(manifest.get("binary"), "machine-IR manifest binary"),
        transfers={row.identity: row for row in transfers},
        units={str(unit["id"]): unit for unit in units},
        unit_inventory={str(row["unit_id"]): row for row in inventory},
    )
    atomic_effect_authority = _atomic_effect_authority(
        semantic_rows,
        transfers={row.identity: row for row in transfers},
    )
    direct_edges = _direct_edges(transfers)
    providers = _runtime_providers(transfers)
    transfer_definedness = analyze_transfer_definedness_v2(transfers)
    payload: dict[str, Any] = {
        "format": EXECUTABLE_TRANSFER_PLAN_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "bindings": {
            "pe_sha256": manifest["binary"]["sha256"],
            "machine_ir_sha256": machine_sha,
            "machine_ir_manifest_sha256": sha256_file(manifest_path),
            "manifest_machine_ir_sha256": manifest["artifacts"]["machine_ir"]["sha256"],
            "unit_inventory_sha256": unit_inventory_sha,
            "exact_universe_sha256": exact_universe_sha,
            "finite_control_routes_sha256": canonical_sha256_v3(
                finite_control_routes
            ),
            "atomic_effect_authority_sha256": canonical_sha256_v3(
                atomic_effect_authority
            ),
        },
        "unit_inventory": inventory,
        "transfers": transfer_rows,
        "direct_control_edges": direct_edges,
        "finite_control_routes": finite_control_routes,
        "atomic_effect_authority": atomic_effect_authority,
        "entry_targets": sorted(row.rva_start for row in transfers),
        "runtime_provider_requirements": providers,
        "operation_registry_sha256": canonical_sha256_v3(
            operation_registry_payload_v2()
        ),
        "diagnostics": {
            "definedness": source_definedness,
            "transfer_definedness": transfer_definedness,
        },
        "semantic_blockers": blockers,
        "counts": {
            "units": len(units),
            "compiled_transfers": len(transfers),
            "direct_control_edges": len(direct_edges),
            "runtime_providers": len(providers),
            "finite_control_routes": len(finite_control_routes),
            "atomic_effects": len(atomic_effect_authority),
            "undefined_nodes": transfer_definedness["counts"]["undefined_nodes"],
            "blockers": len(blockers),
        },
        "authority": "exact_machine_semantics_only",
    }
    payload["plan_sha256"] = canonical_sha256_v3(payload)
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "executable-transfer-plan.json", payload)
    return payload


def parse_executable_transfer_plan(
    value: object, *, require_complete: bool = False
) -> tuple[dict[str, Any], tuple[_Transfer, ...]]:
    payload = _object(value, "executable transfer plan")
    expected_fields = {
        "format", "status", "bindings", "unit_inventory", "transfers",
        "direct_control_edges", "finite_control_routes",
        "atomic_effect_authority", "entry_targets",
        "runtime_provider_requirements",
        "operation_registry_sha256", "diagnostics", "semantic_blockers", "counts",
        "authority", "plan_sha256",
    }
    if set(payload) != expected_fields:
        raise TransferPlanError(
            "executable transfer plan fields are incomplete",
            code="malformed_executable_transfer_plan",
        )
    if payload.get("format") != EXECUTABLE_TRANSFER_PLAN_FORMAT:
        raise TransferPlanError(
            "executable transfer plan format is unsupported",
            code="malformed_executable_transfer_plan",
        )
    core = {key: value for key, value in payload.items() if key != "plan_sha256"}
    if payload.get("plan_sha256") != canonical_sha256_v3(core):
        raise TransferPlanError(
            "executable transfer plan self hash is stale",
            code="stale_executable_transfer_plan",
        )
    blockers = _list(payload.get("semantic_blockers"), "transfer-plan blockers")
    status = payload.get("status")
    if status not in {"complete", "incomplete"} or (
        (status == "complete") != (not blockers)
    ):
        raise TransferPlanError(
            "executable transfer plan status contradicts blockers",
            code="malformed_executable_transfer_plan",
        )
    if require_complete and status != "complete":
        raise TransferPlanError(
            "executable transfer plan remains incomplete",
            code="incomplete_executable_transfer_plan",
        )
    serialized_transfers = tuple(
        _object(raw, f"transfer {index}")
        for index, raw in enumerate(_list(payload.get("transfers"), "transfers"))
    )
    transfers = tuple(_transfer_from_payload(row) for row in serialized_transfers)
    diagnostics = _object(payload.get("diagnostics"), "transfer-plan diagnostics")
    if set(diagnostics) != {"definedness", "transfer_definedness"}:
        raise TransferPlanError(
            "executable transfer-plan diagnostic domains are incomplete",
            code="malformed_executable_transfer_plan",
        )
    if diagnostics["transfer_definedness"] != analyze_transfer_definedness_v2(
        transfers
    ):
        raise TransferPlanError(
            "executable transfer-plan definedness interpretation is stale",
            code="stale_executable_transfer_plan",
        )
    inventory = _list(payload.get("unit_inventory"), "unit inventory")
    bindings = _object(payload.get("bindings"), "transfer-plan bindings")
    finite_control_routes = _list(
        payload.get("finite_control_routes"), "finite control routes"
    )
    _validate_finite_control_routes(
        finite_control_routes,
        transfers={row.identity: row for row in transfers},
        unit_inventory={
            str(_object(row, "unit binding").get("unit_id")): _object(
                row, "unit binding"
            )
            for row in inventory
        },
        pe_sha256=_sha256(
            bindings.get("pe_sha256"), "transfer-plan PE SHA-256"
        ),
    )
    if bindings.get("finite_control_routes_sha256") != canonical_sha256_v3(
        finite_control_routes
    ):
        raise TransferPlanError(
            "executable transfer-plan finite control routes are stale",
            code="stale_executable_transfer_plan",
        )
    atomic_effect_authority = _list(
        payload.get("atomic_effect_authority"), "atomic effect authority"
    )
    _validate_atomic_effect_authority(
        atomic_effect_authority,
        transfers={row.identity: row for row in transfers},
    )
    if bindings.get("atomic_effect_authority_sha256") != canonical_sha256_v3(
        atomic_effect_authority
    ):
        raise TransferPlanError(
            "executable transfer-plan atomic effect authority is stale",
            code="stale_executable_transfer_plan",
        )
    if bindings.get("unit_inventory_sha256") != canonical_sha256_v3(inventory):
        raise TransferPlanError(
            "executable transfer-plan unit inventory is stale",
            code="stale_executable_transfer_plan",
        )
    exact_universe = canonical_sha256_v3({
        "pe_sha256": bindings.get("pe_sha256"),
        "units": [
            {
                "id": _object(row, "unit binding").get("unit_id"),
                "unit_ir_sha256": _sha256(
                    _object(row, "unit binding").get("unit_ir_sha256"),
                    "unit IR SHA-256",
                ),
            }
            for row in sorted(
                inventory,
                key=lambda item: str(_object(item, "unit binding").get("unit_id")),
            )
        ],
    })
    if bindings.get("exact_universe_sha256") != exact_universe:
        raise TransferPlanError(
            "executable transfer-plan exact universe is stale",
            code="stale_executable_transfer_plan",
        )
    compiled_ids = {row.identity for row in transfers}
    inventory_ids = {str(_object(row, "unit binding")["unit_id"]) for row in inventory}
    if not compiled_ids <= inventory_ids or len(compiled_ids) != len(transfers):
        raise TransferPlanError(
            "executable transfers do not uniquely belong to the exact universe",
            code="malformed_executable_transfer_plan",
        )
    inventory_by_id = {
        str(_object(row, "unit binding")["unit_id"]): _object(
            row, "unit binding"
        )
        for row in inventory
    }
    for row in serialized_transfers:
        identity = str(row["identity"])
        binding = inventory_by_id[identity]
        if row["source"] != {
            key: binding[key]
            for key in (
                "rva_start", "rva_end", "unit_ir_sha256", "contract_sha256",
                "instruction_bytes_sha256",
            )
        }:
            raise TransferPlanError(
                f"{identity}: serialized source binding is stale",
                code="stale_executable_transfer_plan",
            )
    transfer_rvas = [row.rva_start for row in transfers]
    if transfer_rvas != sorted(transfer_rvas) or len(set(transfer_rvas)) != len(transfers):
        raise TransferPlanError(
            "executable transfers are not strictly ordered and unique",
            code="malformed_executable_transfer_plan",
        )
    if payload.get("entry_targets") != transfer_rvas:
        raise TransferPlanError(
            "executable transfer-plan entry targets are stale",
            code="stale_executable_transfer_plan",
        )
    counts = _object(payload.get("counts"), "transfer-plan counts")
    expected_counts = {
        "units": len(inventory),
        "compiled_transfers": len(transfers),
        "direct_control_edges": len(_direct_edges(transfers)),
        "runtime_providers": len(_runtime_providers(transfers)),
        "finite_control_routes": len(finite_control_routes),
        "atomic_effects": len(atomic_effect_authority),
        "undefined_nodes": diagnostics["transfer_definedness"]["counts"][
            "undefined_nodes"
        ],
        "blockers": len(blockers),
    }
    if counts != expected_counts:
        raise TransferPlanError(
            "executable transfer-plan counts are stale",
            code="stale_executable_transfer_plan",
        )
    expected_edges = _direct_edges(transfers)
    if payload.get("direct_control_edges") != expected_edges:
        raise TransferPlanError(
            "executable transfer-plan direct edges are stale",
            code="stale_executable_transfer_plan",
        )
    if payload.get("runtime_provider_requirements") != _runtime_providers(transfers):
        raise TransferPlanError(
            "executable transfer-plan runtime providers are stale",
            code="stale_executable_transfer_plan",
        )
    if payload.get("operation_registry_sha256") != canonical_sha256_v3(
        operation_registry_payload_v2()
    ):
        raise TransferPlanError(
            "executable transfer-plan operation registry is stale",
            code="stale_executable_transfer_plan",
        )
    return dict(payload), transfers


def load_executable_transfer_plan(
    path: Path, *, require_complete: bool = False
) -> tuple[dict[str, Any], tuple[_Transfer, ...]]:
    """Load and strictly replay one canonical transfer-v2 artifact."""

    return parse_executable_transfer_plan(
        _load_json(Path(path), "executable transfer plan"),
        require_complete=require_complete,
    )


def _sanitize_source_bindings(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            ("source_span_sha256" if key == "instruction_bytes_sha256" else str(key)):
            _sanitize_source_bindings(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_source_bindings(item) for item in value]
    return value


def _contains_raw_instruction_material(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            (
                key in RAW_INSTRUCTION_FIELDS
                and not (
                    key == "bytes"
                    and isinstance(item, int)
                    and not isinstance(item, bool)
                    and item >= 0
                )
            )
            or _contains_raw_instruction_material(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_raw_instruction_material(item) for item in value)
    return False


def _blocker(
    row: Mapping[str, Any],
    index: int,
    error: TransferPlanError,
    failure_phase: str,
) -> dict[str, Any]:
    original = row.get("original")
    rva = original.get("rva_start") if isinstance(original, Mapping) else None
    return {
        "transfer_index": index,
        "transfer_id": row.get("id") if isinstance(row.get("id"), str) else None,
        "rva_start": rva if isinstance(rva, int) and not isinstance(rva, bool) else None,
        "code": error.code,
        "failure_phase": failure_phase,
        "message": str(error),
        "next_action": error.next_action,
    }


def transfer_blocker_sort_key(
    row: Mapping[str, Any]
) -> tuple[int, str, str, str, int]:
    rva = row.get("rva_start")
    return (
        rva if isinstance(rva, int) else 2**32,
        str(row.get("transfer_id") or ""),
        str(row.get("code") or ""),
        str(row.get("message") or ""),
        int(row.get("transfer_index") or 0),
    )


def _load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferPlanError(f"cannot read {context}: {exc}") from exc
    return dict(_object(value, context))


def _validate_manifest(
    manifest: Mapping[str, Any], units: list[dict[str, Any]], machine_sha: str
) -> None:
    if manifest.get("format") != MACHINE_IR_FORMAT or manifest.get("record_kind") != "manifest":
        raise TransferPlanError(
            "machine-IR manifest format is unsupported",
            code="malformed_machine_ir_manifest",
        )
    binary = _object(manifest.get("binary"), "machine-IR manifest binary")
    _sha256(binary.get("sha256"), "machine-IR PE SHA-256")
    artifact = _object(
        _object(manifest.get("artifacts"), "machine-IR artifacts").get("machine_ir"),
        "machine-IR artifact binding",
    )
    counts = _object(manifest.get("counts"), "machine-IR manifest counts")
    if artifact.get("sha256") != machine_sha or counts.get("units") != len(units):
        raise TransferPlanError(
            "machine-IR manifest binding is stale",
            code="stale_machine_ir_manifest",
        )
    source_map = _list(manifest.get("source_map"), "machine-IR source map")
    expected = sorted(
        (row["unit_id"], row["rva_start"], row["contract_sha256"])
        for row in (_unit_binding(unit) for unit in units)
    )
    observed = sorted(
        (
            _object(row, "machine-IR source-map row").get("unit_id"),
            _object(row, "machine-IR source-map row").get("rva_start"),
            _object(row, "machine-IR source-map row").get("contract_sha256"),
        )
        for row in source_map
    )
    if observed != expected:
        raise TransferPlanError(
            "machine-IR source-map inventory is stale",
            code="stale_machine_ir_manifest",
        )






def _atomic_effect_authority(
    semantic_rows: list[dict[str, Any]],
    *,
    transfers: Mapping[str, _Transfer],
) -> list[dict[str, Any]]:
    """Bind canonical atomic effects to their checked machine-action identity."""

    result: list[dict[str, Any]] = []
    for semantic in semantic_rows:
        unit_id = _string(semantic.get("id"), "atomic-effect unit id")
        transfer = transfers.get(unit_id)
        if transfer is None:
            continue
        graph = _object(
            semantic.get("memory_actions"), f"{unit_id} memory-action graph"
        )
        profile_id = _string(
            graph.get("profile_id"), f"{unit_id} memory-action profile"
        )
        actions = sorted(
            (
                _object(raw, f"{unit_id} atomic action")
                for raw in _list(graph.get("actions"), f"{unit_id} memory actions")
                if isinstance(raw, Mapping) and raw.get("kind") == "rmw"
            ),
            key=lambda row: (
                _u32(row.get("instruction_rva"), "atomic instruction RVA"),
                _string(row.get("id"), "atomic action id"),
            ),
        )
        effects = [
            (index, effect)
            for index, effect in enumerate(transfer.actions[:-1])
            if effect.op in {"atomic_compare_exchange", "atomic_exchange"}
        ]
        if len(actions) != len(effects):
            raise TransferPlanError(
                f"{unit_id}: canonical atomic effects lost machine-action provenance",
                code="atomic_action_coverage_mismatch",
            )
        for action, (effect_index, effect) in zip(actions, effects, strict=True):
            operation = _string(action.get("operation"), "atomic operation")
            expected_op = {
                "compare_exchange": "atomic_compare_exchange",
                "exchange": "atomic_exchange",
            }.get(operation)
            width_bytes = _nonnegative(action.get("width_bytes"), "atomic width")
            if expected_op != effect.op or width_bytes != effect.aux:
                raise TransferPlanError(
                    f"{unit_id}: canonical atomic effect shape changed",
                    code="atomic_action_coverage_mismatch",
                )
            source_indices = [
                _nonnegative(item, "atomic source memory-event index")
                for item in _list(
                    action.get("source_memory_event_indices"),
                    "atomic source memory-event indices",
                )
            ]
            if len(source_indices) != len(set(source_indices)):
                raise TransferPlanError(
                    f"{unit_id}: atomic source event identities are ambiguous",
                    code="malformed_memory_action_graph",
                )
            core = {
                "unit_id": unit_id,
                "effect_index": effect_index,
                "action_id": _string(action.get("id"), "atomic action id"),
                "profile_id": profile_id,
                "instruction_rva": _u32(
                    action.get("instruction_rva"), "atomic instruction RVA"
                ),
                "source_memory_event_indices": source_indices,
                "operation": operation,
                "width_bytes": width_bytes,
            }
            result.append({
                **core,
                "authority_sha256": canonical_sha256_v3(core),
            })
    result.sort(key=lambda row: (row["unit_id"], row["effect_index"]))
    _validate_atomic_effect_authority(result, transfers=transfers)
    return result


def _validate_atomic_effect_authority(
    rows: list[Any],
    *,
    transfers: Mapping[str, _Transfer],
) -> None:
    expected = {
        (unit_id, effect_index): effect
        for unit_id, transfer in transfers.items()
        for effect_index, effect in enumerate(transfer.actions[:-1])
        if effect.op in {"atomic_compare_exchange", "atomic_exchange"}
    }
    observed: dict[tuple[str, int], Mapping[str, Any]] = {}
    action_ids: set[str] = set()
    previous: tuple[str, int] | None = None
    for raw in rows:
        row = _object(raw, "atomic effect authority row")
        if set(row) != {
            "unit_id", "effect_index", "action_id", "profile_id",
            "instruction_rva", "source_memory_event_indices", "operation",
            "width_bytes", "authority_sha256",
        }:
            raise TransferPlanError(
                "atomic effect authority fields are incomplete",
                code="malformed_atomic_effect_authority",
            )
        core = {key: value for key, value in row.items() if key != "authority_sha256"}
        if row.get("authority_sha256") != canonical_sha256_v3(core):
            raise TransferPlanError(
                "atomic effect authority hash is stale",
                code="stale_executable_transfer_plan",
            )
        key = (
            _string(row.get("unit_id"), "atomic effect unit id"),
            _nonnegative(row.get("effect_index"), "atomic effect index"),
        )
        action_id = _string(row.get("action_id"), "atomic action id")
        _string(row.get("profile_id"), "atomic profile id")
        _u32(row.get("instruction_rva"), "atomic instruction RVA")
        source_indices = [
            _nonnegative(item, "atomic source memory-event index")
            for item in _list(
                row.get("source_memory_event_indices"),
                "atomic source memory-event indices",
            )
        ]
        operation = _string(row.get("operation"), "atomic operation")
        width_bytes = _nonnegative(row.get("width_bytes"), "atomic width")
        effect = expected.get(key)
        expected_op = {
            "compare_exchange": "atomic_compare_exchange",
            "exchange": "atomic_exchange",
        }.get(operation)
        if (
            previous is not None and key <= previous
            or key in observed
            or action_id in action_ids
            or source_indices != sorted(set(source_indices))
            or effect is None
            or effect.op != expected_op
            or effect.aux != width_bytes
        ):
            raise TransferPlanError(
                "atomic effect authority is ambiguous or disagrees with the transfer",
                code="malformed_atomic_effect_authority",
            )
        previous = key
        observed[key] = row
        action_ids.add(action_id)
    if set(observed) != set(expected):
        raise TransferPlanError(
            "atomic effect authority does not cover the canonical atomic effects",
            code="malformed_atomic_effect_authority",
        )




def _unit_binding(unit: Mapping[str, Any]) -> dict[str, Any]:
    source = _object(unit.get("source"), "machine-IR unit source")
    original = _object(source.get("original"), "machine-IR unit span")
    return {
        "unit_id": _string(unit.get("id"), "machine-IR unit ID"),
        "unit_ir_sha256": canonical_sha256_v3(unit),
        "rva_start": _u32(original.get("rva_start"), "machine-IR unit RVA"),
        "rva_end": _u32(original.get("rva_end"), "machine-IR unit end RVA"),
        "contract_sha256": _sha256(
            source.get("contract_sha256"), "machine-IR contract SHA-256"
        ),
        "instruction_bytes_sha256": _sha256(
            source.get("instruction_bytes_sha256"),
            "machine-IR instruction SHA-256",
        ),
        "status": unit.get("status"),
    }


def _node_payload(row: _Node, index: int) -> dict[str, Any]:
    spec = expression_operation_v2(row)
    return {
        "id": index,
        "op": row.op,
        "operands": list(row.args),
        "result_sort": spec.result_sort,
        "width_bits": spec.width_bits,
        "parameters": {
            "aux": row.aux,
            "immediate": row.immediate,
            "identity": row.identity,
        },
    }


def _action_payload(row: _Action, index: int) -> dict[str, Any]:
    action_operation_v2(row, terminator=False)
    return {
        "id": index,
        "op": row.op,
        "operands": list(row.args),
        "parameters": {"aux": row.aux},
    }


def _terminator_payload(row: _Action) -> dict[str, Any]:
    action_operation_v2(row, terminator=True)
    return {
        "op": row.op,
        "operands": list(row.args),
        "parameters": {"aux": row.aux},
    }


def _call_payload(row: _Call, index: int) -> dict[str, Any]:
    payload = {
        "id": index,
        "kind": row.kind,
        "instruction_rva": row.instruction_rva,
        "event_index": row.call_index,
        "target_node": row.target_node,
        "target_rva": row.target_rva,
        "return_rva": row.return_rva,
        "dll": row.dll,
        "symbol": row.symbol,
        "ordinal": row.ordinal,
        "register_nodes": list(row.register_nodes),
        "flag_nodes": list(row.flag_nodes),
        "argument_nodes": list(row.argument_nodes),
        "stack_inputs": [list(item) for item in row.stack_inputs],
    }
    if row.native_exception_operations:
        payload["native_exception_operations"] = list(
            row.native_exception_operations
        )
    return payload


def _exception_occurrence_payload(
    row: _ExceptionOccurrence,
) -> dict[str, Any]:
    return {
        "fault_index": row.fault_index,
        "fault_sha256": row.fault_sha256,
        "occurrence_kind": row.occurrence_kind,
        "effect_index": row.effect_index,
        "operation": row.operation,
        "call_id": row.call_id,
        "call_event_index": row.call_event_index,
    }


def _x87_payload(row: _TypedX87Program, index: int) -> dict[str, Any]:
    return {
        "id": index,
        "contract_sha256": row.contract_sha256,
        "image_base": row.image_base,
        "rva_start": row.rva_start,
        "rva_end": row.rva_end,
        "operation": row.operation.payload(),
        "checked_decoder": row.checked_decoder,
        "checked_executor": row.checked_executor,
    }


def _transfer_payload(
    row: _Transfer, unit_binding: Mapping[str, Any]
) -> dict[str, Any]:
    if not row.actions:
        raise TransferPlanError(
            f"{row.identity}: executable transfer has no terminator",
            code="missing_transfer_terminator",
        )
    if row.x87_nodes:
        raise TransferPlanError(
            f"{row.identity}: symbolic x87 expressions are not part of transfer v2",
            code="legacy_x87_expression_unavailable",
            next_action="use qualified typed x87 intrinsics",
        )
    source = {
        "rva_start": row.rva_start,
        "rva_end": unit_binding["rva_end"],
        "unit_ir_sha256": unit_binding["unit_ir_sha256"],
        "contract_sha256": row.contract_sha256,
        "instruction_bytes_sha256": row.instruction_bytes_sha256,
    }
    expected_source = {
        key: unit_binding[key]
        for key in (
            "rva_start", "rva_end", "unit_ir_sha256", "contract_sha256",
            "instruction_bytes_sha256",
        )
    }
    if source != expected_source:
        raise TransferPlanError(
            f"{row.identity}: transfer source binding disagrees with unit inventory",
            code="transfer_source_binding_mismatch",
        )
    effects, terminator = row.actions[:-1], row.actions[-1]
    return {
        "identity": row.identity,
        "source": source,
        "expressions": [
            _node_payload(item, index)
            for index, item in enumerate(row.nodes)
        ],
        "effects": [
            _action_payload(item, index) for index, item in enumerate(effects)
        ],
        "calls": [
            _call_payload(item, index) for index, item in enumerate(row.calls)
        ],
        "exception_occurrences": [
            _exception_occurrence_payload(item)
            for item in row.exception_occurrences
        ],
        "x87_intrinsics": [
            _x87_payload(item, index)
            for index, item in enumerate(row.x87_operations)
        ],
        "terminator": _terminator_payload(terminator),
    }


def _int_tuple(value: object, context: str) -> tuple[int, ...]:
    return tuple(_nonnegative(item, context) for item in _list(value, context))


def _stack_input(value: object) -> tuple[int, int, int]:
    items = _int_tuple(value, "stack input")
    if len(items) != 3 or items[1] not in {1, 2, 4}:
        raise TransferPlanError(
            "serialized stack input must contain offset, width, and value node",
            code="malformed_transfer_width",
        )
    return items


def _parameters(value: object, fields: set[str], context: str) -> dict[str, Any]:
    result = _object(value, context)
    if set(result) != fields:
        raise TransferPlanError(
            f"{context} fields are incomplete",
            code="malformed_executable_transfer_plan",
        )
    return result


def _node_from_payload(raw: object, index: int) -> _Node:
    context = f"expression {index}"
    value = _object(raw, context)
    if set(value) != {
        "id", "op", "operands", "result_sort", "width_bits", "parameters"
    } or value.get("id") != index:
        raise TransferPlanError(
            f"{context} fields or dense ID are invalid",
            code="malformed_executable_transfer_plan",
        )
    parameters = _parameters(
        value.get("parameters"),
        {"aux", "immediate", "identity"},
        f"{context} parameters",
    )
    node = _Node(
        _string(value.get("op"), f"{context} op"),
        _int_tuple(value.get("operands"), f"{context} operands"),
        _nonnegative(parameters.get("aux"), f"{context} aux"),
        _nonnegative(parameters.get("immediate"), f"{context} immediate"),
        _optional_string(parameters.get("identity"), f"{context} identity"),
    )
    spec = expression_operation_v2(node)
    if (
        value.get("result_sort") != spec.result_sort
        or value.get("width_bits") != spec.width_bits
    ):
        raise TransferPlanError(
            f"{context} type metadata disagrees with the operation registry",
            code="malformed_transfer_type",
        )
    if (node.op in {"undefined_bv", "undefined_flag"}) != (
        node.identity is not None
    ):
        raise TransferPlanError(
            f"{context} stable undefined identity is missing or contradictory",
            code="malformed_transfer_undefined_identity",
        )
    if any(operand >= index for operand in node.args):
        raise TransferPlanError(
            f"{context} does not form a dense acyclic expression graph",
            code="malformed_transfer_node_reference",
        )
    return node


def _action_from_payload(
    raw: object,
    index: int,
    *,
    terminator: bool,
    expression_count: int,
    call_count: int,
    x87_intrinsic_count: int,
) -> _Action:
    context = "terminator" if terminator else f"effect {index}"
    value = _object(raw, context)
    expected = {"op", "operands", "parameters"}
    if not terminator:
        expected.add("id")
    if set(value) != expected or (
        not terminator and value.get("id") != index
    ):
        raise TransferPlanError(
            f"{context} fields or dense ID are invalid",
            code="malformed_executable_transfer_plan",
        )
    parameters = _parameters(
        value.get("parameters"), {"aux"}, f"{context} parameters"
    )
    action = _Action(
        _string(value.get("op"), f"{context} op"),
        _int_tuple(value.get("operands"), f"{context} operands"),
        _nonnegative(parameters.get("aux"), f"{context} aux"),
    )
    action_operation_v2(action, terminator=terminator)
    if terminator:
        references = (
            action.args[:1]
            if action.op == "outcome_branch"
            else action.args
            if action.op in {
                "outcome_return", "outcome_indirect", "outcome_nonlocal",
            }
            else ()
        )
        if any(reference >= expression_count for reference in references):
            raise TransferPlanError(
                "transfer terminator references an unknown expression",
                code="malformed_transfer_node_reference",
            )
        return action
    if action.op == "call":
        if action.args[0] >= call_count:
            raise TransferPlanError(
                "call effect references an unknown call",
                code="malformed_transfer_call_reference",
            )
        return action
    if action.op == "typed_x87":
        if action.args[0] >= x87_intrinsic_count:
            raise TransferPlanError(
                "typed x87 effect references an unknown intrinsic",
                code="malformed_transfer_x87_reference",
            )
        return action
    if any(reference >= expression_count for reference in action.args):
        raise TransferPlanError(
            f"{context} references an unknown expression",
            code="malformed_transfer_node_reference",
        )
    return action


def _optional_string(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _string(value, context)


def _transfer_from_payload(row: Mapping[str, Any]) -> _Transfer:
    expected = {
        "identity", "source", "expressions", "effects",
        "calls", "exception_occurrences", "x87_intrinsics", "terminator",
    }
    if set(row) != expected:
        raise TransferPlanError(
            "serialized transfer fields are incomplete",
            code="malformed_executable_transfer_plan",
        )
    source = _object(row.get("source"), "transfer source")
    if set(source) != {
        "rva_start", "rva_end", "unit_ir_sha256", "contract_sha256",
        "instruction_bytes_sha256",
    }:
        raise TransferPlanError(
            "serialized transfer source fields are incomplete",
            code="malformed_executable_transfer_plan",
        )
    rva_start = _u32(source.get("rva_start"), "transfer RVA")
    rva_end = _u32(source.get("rva_end"), "transfer end RVA")
    _sha256(source.get("unit_ir_sha256"), "transfer unit IR SHA-256")
    if rva_end <= rva_start:
        raise TransferPlanError(
            "serialized transfer source range is empty",
            code="malformed_executable_transfer_plan",
        )
    expressions = tuple(
        _node_from_payload(raw, index)
        for index, raw in enumerate(_list(row.get("expressions"), "expressions"))
    )
    calls: list[_Call] = []
    call_fields = {
        "id", "kind", "instruction_rva", "event_index", "target_node",
        "target_rva", "return_rva", "dll", "symbol", "ordinal",
        "register_nodes", "flag_nodes", "argument_nodes", "stack_inputs",
    }
    for index, raw in enumerate(_list(row.get("calls"), "transfer calls")):
        value = _object(raw, f"transfer call {index}")
        optional_call_fields = {"native_exception_operations"}
        if (
            not call_fields <= set(value)
            or set(value) - call_fields - optional_call_fields
            or value.get("id") != index
        ):
            raise TransferPlanError(
                f"transfer call {index} fields or dense ID are invalid",
                code="malformed_executable_transfer_plan",
            )
        target_node = (
            None
            if value.get("target_node") is None
            else _nonnegative(value.get("target_node"), "call target node")
        )
        register_nodes = _int_tuple(
            value.get("register_nodes"), "register nodes"
        )
        flag_nodes = _int_tuple(value.get("flag_nodes"), "flag nodes")
        if len(register_nodes) != len(_REGISTERS) or len(flag_nodes) != len(
            _FLAGS
        ):
            raise TransferPlanError(
                f"transfer call {index} has a malformed physical state frame",
                code="malformed_transfer_call_frame",
            )
        argument_nodes = _int_tuple(
            value.get("argument_nodes"), "argument nodes"
        )
        stack_inputs = tuple(
            _stack_input(item)
            for item in _list(value.get("stack_inputs"), "stack inputs")
        )
        references = (
            *(() if target_node is None else (target_node,)),
            *register_nodes,
            *flag_nodes,
            *argument_nodes,
            *(item[2] for item in stack_inputs),
        )
        if any(reference >= len(expressions) for reference in references):
            raise TransferPlanError(
                f"transfer call {index} references an unknown expression",
                code="malformed_transfer_node_reference",
            )
        ordinal = value.get("ordinal")
        kind = _string(value.get("kind"), "transfer call kind")
        native_exception_operations = native_exception_operations_for_call_v2(
            value, strict_list=True, context="call"
        )
        calls.append(_Call(
            kind=kind,
            instruction_rva=_u32(value.get("instruction_rva"), "call RVA"),
            call_index=_nonnegative(value.get("event_index"), "call event index"),
            target_node=target_node,
            target_rva=_u32(value.get("target_rva"), "call target RVA"),
            return_rva=_u32(value.get("return_rva"), "call return RVA"),
            dll=_optional_string(value.get("dll"), "call DLL"),
            symbol=_optional_string(value.get("symbol"), "call symbol"),
            ordinal=(
                None if ordinal is None
                else _nonnegative(ordinal, "call ordinal")
            ),
            register_nodes=register_nodes,
            flag_nodes=flag_nodes,
            argument_nodes=argument_nodes,
            stack_inputs=stack_inputs,
            native_exception_operations=native_exception_operations,
        ))
    x87_rows: list[_TypedX87Program] = []
    x87_fields = {
        "id", "contract_sha256", "image_base", "rva_start", "rva_end",
        "operation", "checked_decoder", "checked_executor",
    }
    for index, raw in enumerate(
        _list(row.get("x87_intrinsics"), "x87 intrinsics")
    ):
        value = _object(raw, f"x87 intrinsic {index}")
        if set(value) != x87_fields or value.get("id") != index:
            raise TransferPlanError(
                f"x87 intrinsic {index} fields or dense ID are invalid",
                code="malformed_executable_transfer_plan",
            )
        image_base = _u32(value.get("image_base"), "x87 image base")
        operation = typed_x87_operation_from_payload(
            _object(value.get("operation"), "typed x87 operation"),
            image_base=image_base,
        )
        rva = _u32(value.get("rva_start"), "x87 RVA")
        rva_end = _u32(value.get("rva_end"), "x87 end RVA")
        if rva_end <= rva:
            raise TransferPlanError(
                "x87 intrinsic source range is empty",
                code="malformed_executable_transfer_plan",
            )
        x87_rows.append(_TypedX87Program(
            contract_sha256=_sha256(value.get("contract_sha256"), "x87 contract"),
            image_base=image_base,
            rva_start=rva,
            rva_end=rva_end,
            operation=operation,
            checked_decoder=_string(value.get("checked_decoder"), "x87 decoder"),
            checked_executor=_string(value.get("checked_executor"), "x87 executor"),
        ))
    effects_raw = _list(row.get("effects"), "transfer effects")
    effects = tuple(
        _action_from_payload(
            raw,
            index,
            terminator=False,
            expression_count=len(expressions),
            call_count=len(calls),
            x87_intrinsic_count=len(x87_rows),
        )
        for index, raw in enumerate(effects_raw)
    )
    terminator = _action_from_payload(
        row.get("terminator"),
        len(effects),
        terminator=True,
        expression_count=len(expressions),
        call_count=len(calls),
        x87_intrinsic_count=len(x87_rows),
    )
    occurrence_fields = {
        "fault_index", "fault_sha256", "occurrence_kind", "effect_index",
        "operation", "call_id", "call_event_index",
    }
    exception_occurrences: list[_ExceptionOccurrence] = []
    for fault_index, raw in enumerate(
        _list(row.get("exception_occurrences"), "exception occurrences")
    ):
        value = _object(raw, f"exception occurrence {fault_index}")
        if set(value) != occurrence_fields or value.get("fault_index") != fault_index:
            raise TransferPlanError(
                "exception occurrence fields or dense identity are invalid",
                code="malformed_exception_occurrence_inventory",
            )
        occurrence_kind = _string(
            value.get("occurrence_kind"), "exception occurrence kind"
        )
        effect_index = _nonnegative(
            value.get("effect_index"), "exception occurrence effect index"
        )
        operation = _string(
            value.get("operation"), "exception occurrence operation"
        )
        call_id_raw = value.get("call_id")
        call_event_raw = value.get("call_event_index")
        call_id = (
            None if call_id_raw is None
            else _nonnegative(call_id_raw, "exception occurrence call ID")
        )
        call_event_index = (
            None if call_event_raw is None
            else _nonnegative(
                call_event_raw, "exception occurrence call event index"
            )
        )
        if effect_index >= len(effects):
            raise TransferPlanError(
                "exception occurrence references an unknown effect",
                code="malformed_exception_occurrence_inventory",
            )
        effect = effects[effect_index]
        if occurrence_kind == "effect":
            valid = (
                call_id is None
                and call_event_index is None
                and effect.op == operation
                and effect.op in NATIVE_EXCEPTION_EFFECTS_V2
                and effect.aux == fault_index
            )
        elif occurrence_kind == "call":
            valid = (
                call_id is not None
                and call_event_index is not None
                and call_id < len(calls)
                and effect.op == "call"
                and effect.args == (call_id,)
                and calls[call_id].call_index == call_event_index
                and operation in calls[call_id].native_exception_operations
            )
        else:
            valid = False
        if not valid:
            raise TransferPlanError(
                "exception occurrence contradicts its executable effect",
                code="malformed_exception_occurrence_inventory",
            )
        exception_occurrences.append(_ExceptionOccurrence(
            fault_index=fault_index,
            fault_sha256=_sha256(
                value.get("fault_sha256"), "exception occurrence SHA-256"
            ),
            occurrence_kind=occurrence_kind,
            effect_index=effect_index,
            operation=operation,
            call_id=call_id,
            call_event_index=call_event_index,
        ))
    expected_occurrences = sum(
        effect.op in NATIVE_EXCEPTION_EFFECTS_V2 for effect in effects
    ) + sum(len(call.native_exception_operations) for call in calls)
    if len(exception_occurrences) != expected_occurrences:
        raise TransferPlanError(
            "exception occurrence inventory does not cover executable effects",
            code="malformed_exception_occurrence_inventory",
        )
    return _Transfer(
        identity=_string(row.get("identity"), "transfer identity"),
        contract_sha256=_sha256(
            source.get("contract_sha256"), "transfer contract"
        ),
        instruction_bytes_sha256=_sha256(
            source.get("instruction_bytes_sha256"), "transfer instruction bytes"
        ),
        rva_start=rva_start,
        nodes=expressions,
        x87_nodes=(),
        actions=(*effects, terminator),
        calls=tuple(calls),
        exception_occurrences=tuple(exception_occurrences),
        x87_operations=tuple(x87_rows),
    )

def _direct_edges(transfers: Iterable[_Transfer]) -> list[dict[str, int | str]]:
    edges: list[dict[str, int | str]] = []
    for transfer in transfers:
        if transfer.actions:
            outcome = transfer.actions[-1]
            targets = (
                outcome.args[:1]
                if outcome.op in {"outcome_fallthrough", "outcome_jump"}
                else outcome.args[1:3] if outcome.op == "outcome_branch" else ()
            )
            for target in targets:
                edges.append({
                    "kind": "control",
                    "source_rva": transfer.rva_start,
                    "target_rva": target,
                })
        for call in transfer.calls:
            if call.kind == "internal_call":
                edges.append({
                    "kind": "internal_call",
                    "source_rva": transfer.rva_start,
                    "target_rva": call.target_rva,
                })
    return sorted(edges, key=lambda row: (
        int(row["source_rva"]), str(row["kind"]), int(row["target_rva"])
    ))


def _runtime_providers(transfers: Iterable[_Transfer]) -> list[str]:
    return runtime_provider_requirements_v2(transfers, layer="transfer_plan")


__all__ = [
    "adapt_exact_machine_ir_rows",
    "compile_exact_machine_ir",
    "compile_transfer_rows",
    "load_executable_transfer_plan",
    "parse_executable_transfer_plan",
    "transfer_blocker_sort_key",
    "write_executable_transfer_plan",
]
