"""Check and materialize the adapter used by component evidence and runtime."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.formats import MACHINE_IR_FORMAT
from ..external.contracts import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    parse_checked_external_site_contract,
)
from ..util import sha256_file, write_json
from .formats import (
    COMPONENT_ADAPTER_PLAN_V1_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
)
from .intent import ComponentIntentError
from .logical_abi import LOGICAL_OBJECT_C_V1, logical_abi_header
from .source import load_component_source_package


_STATE_FIELDS = (
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "cf",
    "zf",
    "sf",
    "of",
    "pf",
    "df",
)
_SUPPORTED_COMPLETION_OPS = frozenset(
    {
        "add_overflow",
        "add32",
        "and32",
        "const",
        "entry",
        "eq",
        "external_result",
        "false",
        "ite",
        "load",
        "logical_result",
        "msb",
        "not",
        "or32",
        "parity",
        "sub_overflow",
        "sub32",
        "true",
        "ult32",
        "xor32",
    }
)


def build_component_adapter_plan(
    *,
    contract: Path | str,
    implementation: Path | str,
    machine_ir: Path | str,
    out_dir: Path | str,
) -> dict[str, object]:
    """Emit a checked, hash-bound lowering plan before evidence can qualify."""

    contract_root = Path(contract)
    contract_payload = _read_object(
        contract_root / "contract.json", "component contract"
    )
    _check_self_hash(
        contract_payload,
        COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
        "contract_sha256",
        "component contract",
    )
    source = load_component_source_package(implementation)
    machine_path, machine_manifest_path, machine = _load_machine_ir(Path(machine_ir))
    interface = _read_object(
        contract_root / "reviewed-interface.json", "reviewed component interface"
    )
    catalog = _read_object(
        contract_root / "semantic-component-catalog.json",
        "semantic component catalog",
    )
    lift_unit = _object(contract_payload.get("lift_unit"), "contract lift unit")
    identity = _string(lift_unit.get("id"), "component id")
    member_ids = tuple(
        _string(value, "component member id")
        for value in _array(lift_unit.get("unit_ids"), "component member ids")
    )
    issues: list[dict[str, object]] = []
    if contract_payload.get("status") != "checked":
        _issue(issues, "incomplete", "component_contract_not_checked")
    if source.get("lift_unit_id") != identity:
        _issue(issues, "violated", "component_source_identity_mismatch")
    missing = sorted(set(member_ids) - set(machine))
    if missing:
        _issue(
            issues,
            "violated",
            "component_machine_members_missing",
            missing=missing,
        )

    entry_ids: list[str] = []
    lowering: dict[str, object] = {}
    external_contracts = _external_contract_index(interface, issues)
    if not missing:
        members = {member_id: machine[member_id] for member_id in member_ids}
        entry_ids = _contract_entries(catalog, identity)
        source_entry = _object(source.get("entry"), "component source entry")
        abi = source_entry.get("abi")
        if interface.get("source_abi", "logical-c-v1") != abi:
            _issue(
                issues,
                "violated",
                "component_interface_source_abi_mismatch",
                expected=abi,
                observed=interface.get("source_abi"),
            )
        if len(entry_ids) != 1:
            _issue(
                issues,
                "incomplete",
                "component_adapter_requires_one_entry",
                observed=entry_ids,
            )
        elif abi == "logical-c-v1":
            lowering = _scalar_lowering(
                members,
                entry_ids[0],
                interface,
                external_contracts,
                issues,
            )
        elif abi == LOGICAL_OBJECT_C_V1:
            lowering = _object_lowering(
                members,
                entry_ids[0],
                interface,
                external_contracts,
                issues,
            )
        else:
            _issue(
                issues,
                "incomplete",
                "component_source_abi_not_lowerable",
                observed=abi,
            )

    external_calls = _array(
        lowering.get("external_calls", []), "component adapter external calls"
    )
    external_replay = lowering.get("external_replay")
    external_calls_emitted = not external_calls or (
        isinstance(external_replay, Mapping)
        and external_replay.get("kind") == "linear-read-only-call-v1"
    )
    if not external_calls_emitted:
        _issue(
            issues,
            "incomplete",
            "component_runtime_external_calls_not_lowerable",
            sites=[
                {
                    "unit_id": _object(row, "component adapter external call").get(
                        "unit_id"
                    ),
                    "event_index": _object(
                        row, "component adapter external call"
                    ).get("event_index"),
                }
                for row in external_calls
            ],
        )

    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    header = output / "spaghetti-component-abi.h"
    header.write_text(logical_abi_header(), encoding="ascii")
    core: dict[str, object] = {
        "format": COMPONENT_ADAPTER_PLAN_V1_FORMAT,
        "status": status,
        "lift_unit_id": identity,
        "executes_original_binary": False,
        "bindings": {
            "contract_sha256": contract_payload["contract_sha256"],
            "implementation_sha256": source["implementation_sha256"],
            "machine_ir_sha256": sha256_file(machine_path),
            "machine_ir_manifest_sha256": sha256_file(machine_manifest_path),
            "source_entry": copy.deepcopy(source.get("entry")),
        },
        "entry_unit_ids": entry_ids,
        "lowering": lowering,
        "artifacts": {
            "logical_abi_header": {
                "path": header.name,
                "sha256": sha256_file(header),
            }
        },
        "policy": {
            "portable_source_called_once": True,
            "machine_ir_fallback_used": False,
            "runtime_completion": (
                "checked-machine-projection-v1"
                if lowering.get("kind")
                in {
                    "scalar-machine-projection-v1",
                    "scalar-control-projection-v1",
                }
                else "explicit-reviewed-completion-v1"
                if lowering.get("kind") == "checked-object-view-v1"
                else None
            ),
            "raw_machine_addresses_exposed": False,
            "fallback_on_unimplemented": False,
            "external_calls_emitted": external_calls_emitted,
        },
        "issues": sorted(
            issues, key=lambda row: (str(row["status"]), str(row["code"]))
        ),
    }
    result = {**core, "adapter_plan_sha256": _canonical_sha256(core)}
    write_json(output / "adapter-plan.json", result)
    return result


def load_component_adapter_plan(value: Path | str) -> dict[str, object]:
    root = Path(value)
    path = root / "adapter-plan.json" if root.is_dir() else root
    payload = _read_object(path, "component adapter plan")
    _check_self_hash(
        payload,
        COMPONENT_ADAPTER_PLAN_V1_FORMAT,
        "adapter_plan_sha256",
        "component adapter plan",
    )
    artifact = _object(
        _object(payload.get("artifacts"), "adapter artifacts").get(
            "logical_abi_header"
        ),
        "logical ABI header artifact",
    )
    header = path.parent / _string(artifact.get("path"), "logical ABI header path")
    if not header.is_file() or artifact.get("sha256") != sha256_file(header):
        raise ComponentIntentError("component logical ABI header binding is stale")
    return payload


def _scalar_lowering(
    members: Mapping[str, Mapping[str, object]],
    entry_id: str,
    interface: Mapping[str, object],
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
    issues: list[dict[str, object]],
) -> dict[str, object]:
    path: list[str] = []
    seen: set[str] = set()
    by_rva = {_unit_rva(row): row for row in members.values()}
    current = members[entry_id]
    while True:
        identity = _string(current.get("id"), "machine unit id")
        if identity in seen:
            _issue(issues, "incomplete", "scalar_adapter_path_contains_cycle")
            break
        seen.add(identity)
        path.append(identity)
        semantics = _object(current.get("semantics"), "machine semantics")
        for event_index, _event in enumerate(
            _array(semantics.get("external_events", []), "external events")
        ):
            if (identity, event_index) not in external_contracts:
                _issue(
                    issues,
                    "incomplete",
                    "scalar_adapter_external_event_uncontracted",
                    unit_id=identity,
                    event_index=event_index,
                )
        if _array(semantics.get("faults", []), "fault inventory"):
            _issue(issues, "incomplete", "scalar_adapter_faulting_path")
        if any(
            _object(event, "memory event").get("kind") != "read"
            for event in _array(semantics.get("memory_events", []), "memory events")
        ):
            _issue(issues, "incomplete", "scalar_adapter_memory_write")
        outcome = _object(semantics.get("outcome"), "machine outcome")
        kind = outcome.get("kind")
        if kind == "return":
            return {
                "kind": "scalar-machine-projection-v1",
                "path_unit_ids": path,
                "external_calls": _external_call_payloads(members, external_contracts),
            }
        if kind == "branch":
            targets = (outcome.get("true_target_rva"), outcome.get("false_target_rva"))
            if any(not isinstance(target, int) for target in targets):
                _issue(issues, "violated", "scalar_adapter_branch_target_malformed")
            elif any(target in by_rva for target in targets):
                _issue(
                    issues,
                    "incomplete",
                    "scalar_adapter_internal_branch_not_lowerable",
                    observed=list(targets),
                )
            result_id = _check_scalar_control_result(
                interface,
                unit_id=identity,
                outcome=outcome,
                issues=issues,
            )
            return {
                "kind": "scalar-control-projection-v1",
                "path_unit_ids": path,
                "external_calls": _external_call_payloads(members, external_contracts),
                "logical_result_id": result_id,
                "branch": {
                    "unit_id": identity,
                    "condition": copy.deepcopy(outcome.get("condition")),
                    "true_target_rva": outcome.get("true_target_rva"),
                    "false_target_rva": outcome.get("false_target_rva"),
                },
            }
        if kind not in {"fallthrough", "jump"}:
            _issue(
                issues,
                "incomplete",
                "scalar_adapter_non_linear_control",
                observed=kind,
            )
            break
        target = outcome.get("target_rva")
        if not isinstance(target, int) or target not in by_rva:
            _issue(issues, "incomplete", "scalar_adapter_exits_component")
            break
        current = by_rva[target]
    return {
        "kind": "scalar-machine-projection-v1",
        "path_unit_ids": path,
        "external_calls": _external_call_payloads(members, external_contracts),
    }


def _check_scalar_control_result(
    interface: Mapping[str, object],
    *,
    unit_id: str,
    outcome: Mapping[str, object],
    issues: list[dict[str, object]],
) -> str | None:
    results = [
        _object(row, "logical result")
        for row in _array(interface.get("results"), "logical results")
    ]
    values = [row for row in results if row.get("kind") == "value"]
    controls = [row for row in results if row.get("kind") == "control"]
    if len(values) != 1 or len(controls) != 1:
        _issue(
            issues,
            "incomplete",
            "scalar_control_result_inventory_not_canonical",
            expected={"value_results": 1, "control_results": 1},
            observed={"value_results": len(values), "control_results": len(controls)},
        )
        return None
    result = values[0]
    source = _object(result.get("machine_source"), "logical control source")
    evidence = _object(source.get("evidence"), "logical control evidence")
    if (
        source.get("kind") != "expression"
        or source.get("expression") != outcome.get("condition")
        or evidence.get("unit_id") != unit_id
        or evidence.get("json_pointer") != "/semantics/outcome/condition"
    ):
        _issue(
            issues,
            "violated",
            "scalar_control_condition_binding_mismatch",
            expected={
                "unit_id": unit_id,
                "json_pointer": "/semantics/outcome/condition",
                "expression": outcome.get("condition"),
            },
            observed=copy.deepcopy(dict(source)),
        )
    if _array(result.get("effect_refs", []), "logical control result effects"):
        _issue(
            issues,
            "violated",
            "scalar_control_result_owns_machine_effect",
        )
    control = _object(controls[0].get("control"), "logical control result")
    if (
        control.get("unit_id") != unit_id
        or control.get("outcome_kind") != "branch"
        or control.get("condition") != outcome.get("condition")
        or control.get("routes")
        != [
            {"target_rva": outcome.get("true_target_rva"), "when": True},
            {"target_rva": outcome.get("false_target_rva"), "when": False},
        ]
    ):
        _issue(issues, "violated", "scalar_control_exit_binding_mismatch")
    identity = result.get("id")
    if not isinstance(identity, str) or not identity:
        _issue(issues, "violated", "scalar_control_result_id_malformed")
        return None
    return identity


def _object_lowering(
    members: Mapping[str, Mapping[str, object]],
    entry_id: str,
    interface: Mapping[str, object],
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
    issues: list[dict[str, object]],
) -> dict[str, object]:
    member_rvas = {_unit_rva(row) for row in members.values()}
    reachable: set[int] = set()
    pending = [_unit_rva(members[entry_id])]
    by_rva = {_unit_rva(row): row for row in members.values()}
    return_count = 0
    while pending:
        rva = pending.pop()
        if rva in reachable:
            continue
        reachable.add(rva)
        semantics = _object(by_rva[rva].get("semantics"), "machine semantics")
        unit_id = _string(by_rva[rva].get("id"), "machine unit id")
        for event_index, _event in enumerate(
            _array(semantics.get("external_events", []), "external events")
        ):
            if (unit_id, event_index) not in external_contracts:
                _issue(
                    issues,
                    "incomplete",
                    "object_adapter_external_event_uncontracted",
                    unit_id=unit_id,
                    event_index=event_index,
                )
        if _array(semantics.get("faults", []), "fault inventory"):
            _issue(issues, "incomplete", "object_adapter_faulting_path")
        for event in _array(semantics.get("memory_events", []), "memory events"):
            row = _object(event, "memory event")
            if row.get("kind") == "write" and not _is_stack_expression(
                row.get("address")
            ):
                _issue(issues, "incomplete", "object_adapter_non_stack_write")
        outcome = _object(semantics.get("outcome"), "machine outcome")
        kind = outcome.get("kind")
        targets: list[object]
        if kind in {"fallthrough", "jump"}:
            targets = [outcome.get("target_rva")]
        elif kind == "branch":
            targets = [outcome.get("true_target_rva"), outcome.get("false_target_rva")]
        elif kind == "return":
            return_count += 1
            targets = []
        else:
            _issue(
                issues,
                "incomplete",
                "object_adapter_control_not_lowerable",
                observed=kind,
            )
            targets = []
        for target in targets:
            if not isinstance(target, int) or target not in member_rvas:
                _issue(
                    issues,
                    "incomplete",
                    "object_adapter_exits_component",
                    observed=target,
                )
            elif target not in reachable:
                pending.append(target)
    if reachable != member_rvas:
        _issue(
            issues,
            "incomplete",
            "object_adapter_members_not_entry_reachable",
            missing=sorted(member_rvas - reachable),
        )
    if return_count == 0:
        _issue(issues, "incomplete", "object_adapter_has_no_return")
    completion = interface.get("completion")
    normalized_completion = _check_completion(
        completion, interface, external_contracts, issues
    )
    external_replay = _linear_external_replay(
        members,
        entry_id,
        external_contracts,
        issues,
    )
    return {
        "kind": "checked-object-view-v1",
        "member_unit_ids": sorted(members),
        "external_calls": _external_call_payloads(members, external_contracts),
        "external_replay": external_replay,
        "completion": normalized_completion,
    }


def _linear_external_replay(
    members: Mapping[str, Mapping[str, object]],
    entry_id: str,
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
    issues: list[dict[str, object]],
) -> dict[str, object] | None:
    calls = sorted(
        key for key in external_contracts if key[0] in members
    )
    if not calls:
        return None
    if len(calls) != 1:
        _issue(
            issues,
            "incomplete",
            "component_runtime_external_call_sequence_not_lowerable",
            observed=[{"unit_id": unit_id, "event_index": index} for unit_id, index in calls],
        )
        return None
    call_unit_id, call_event_index = calls[0]
    contract = external_contracts[calls[0]]
    identity = contract.identity
    supported_contract = (
        contract.transfer_kind == "call"
        and contract.disposition == "returns_here"
        and contract.profile_disposition == "returns"
        and contract.abi_template in {"pe32-cdecl-v1", "pe32-stdcall-v1"}
        and identity.kind == "import"
        and identity.dll is not None
        and (identity.symbol is not None or identity.ordinal is not None)
        and contract.memory_effect in {"none", "readOnly"}
        and contract.world_effect == "none"
        and contract.callback_effect == "none"
        and contract.callback_adapter is None
        and not contract.out_pointer_relations
        and not contract.out_interface_relations
        and tuple(argument.index for argument in contract.stack_arguments)
        == tuple(range(contract.argument_words))
        and all(argument.width == 4 for argument in contract.stack_arguments)
    )
    if not supported_contract:
        _issue(
            issues,
            "incomplete",
            "component_runtime_external_contract_not_replayable",
            unit_id=call_unit_id,
            event_index=call_event_index,
            contract_id=contract.contract_id,
        )
        return None

    by_rva = {_unit_rva(row): row for row in members.values()}
    current = members[entry_id]
    prefix: list[str] = []
    seen: set[str] = set()
    while True:
        unit_id = _string(current.get("id"), "external replay unit id")
        if unit_id in seen:
            _issue(
                issues,
                "incomplete",
                "component_runtime_external_call_prefix_contains_cycle",
                unit_id=unit_id,
            )
            return None
        seen.add(unit_id)
        prefix.append(unit_id)
        semantics = _object(current.get("semantics"), "machine semantics")
        if _array(semantics.get("faults", []), "fault inventory"):
            _issue(
                issues,
                "incomplete",
                "component_runtime_external_call_prefix_may_fault",
                unit_id=unit_id,
            )
            return None
        events = _array(semantics.get("external_events", []), "external events")
        if unit_id == call_unit_id:
            if call_event_index >= len(events):
                _issue(
                    issues,
                    "violated",
                    "component_runtime_external_call_reference_stale",
                    unit_id=unit_id,
                    event_index=call_event_index,
                )
                return None
            if call_event_index != 0 or len(events) != 1:
                _issue(
                    issues,
                    "incomplete",
                    "component_runtime_external_call_unit_not_linear",
                    unit_id=unit_id,
                    observed=len(events),
                )
                return None
            if _unit_reachable_from_own_exit(
                call_unit_id=call_unit_id,
                call_unit=current,
                members=members,
                by_rva=by_rva,
            ):
                _issue(
                    issues,
                    "incomplete",
                    "component_runtime_external_call_may_repeat",
                    unit_id=call_unit_id,
                    event_index=call_event_index,
                )
                return None
            return {
                "kind": "linear-read-only-call-v1",
                "prefix_unit_ids": prefix,
                "call": {
                    "unit_id": call_unit_id,
                    "event_index": call_event_index,
                    "contract_id": contract.contract_id,
                },
            }
        if events:
            _issue(
                issues,
                "incomplete",
                "component_runtime_external_call_prefix_has_unplanned_event",
                unit_id=unit_id,
            )
            return None
        outcome = _object(semantics.get("outcome"), "machine outcome")
        if outcome.get("kind") not in {"fallthrough", "jump"}:
            _issue(
                issues,
                "incomplete",
                "component_runtime_external_call_prefix_control_not_linear",
                unit_id=unit_id,
                observed=outcome.get("kind"),
            )
            return None
        target = outcome.get("target_rva")
        if not isinstance(target, int) or target not in by_rva:
            _issue(
                issues,
                "incomplete",
                "component_runtime_external_call_prefix_exits_component",
                unit_id=unit_id,
                observed=target,
            )
            return None
        current = by_rva[target]


def _unit_reachable_from_own_exit(
    *,
    call_unit_id: str,
    call_unit: Mapping[str, object],
    members: Mapping[str, Mapping[str, object]],
    by_rva: Mapping[int, Mapping[str, object]],
) -> bool:
    pending = list(
        _internal_outcome_targets(
            _object(call_unit.get("semantics"), "machine semantics"), by_rva
        )
    )
    visited: set[str] = set()
    while pending:
        unit = pending.pop()
        unit_id = _string(unit.get("id"), "external replay successor unit")
        if unit_id == call_unit_id:
            return True
        if unit_id in visited or unit_id not in members:
            continue
        visited.add(unit_id)
        pending.extend(
            _internal_outcome_targets(
                _object(unit.get("semantics"), "machine semantics"), by_rva
            )
        )
    return False


def _internal_outcome_targets(
    semantics: Mapping[str, object],
    by_rva: Mapping[int, Mapping[str, object]],
) -> list[Mapping[str, object]]:
    outcome = _object(semantics.get("outcome"), "machine outcome")
    kind = outcome.get("kind")
    if kind in {"fallthrough", "jump"}:
        targets = [outcome.get("target_rva")]
    elif kind == "branch":
        targets = [outcome.get("true_target_rva"), outcome.get("false_target_rva")]
    else:
        targets = []
    return [by_rva[target] for target in targets if isinstance(target, int) and target in by_rva]


def _external_contract_index(
    interface: Mapping[str, object],
    issues: list[dict[str, object]],
) -> dict[tuple[str, int], CheckedExternalSiteContract]:
    result: dict[tuple[str, int], CheckedExternalSiteContract] = {}
    for service_index, raw_service in enumerate(
        _array(interface.get("services", []), "component services")
    ):
        service = _object(raw_service, "component service")
        raw_contract = service.get("external_contract")
        if raw_contract is None:
            continue
        if not isinstance(raw_contract, Mapping):
            _issue(
                issues,
                "violated",
                "component_external_contract_malformed",
                service_index=service_index,
            )
            continue
        try:
            contract = parse_checked_external_site_contract(
                raw_contract,
                context=f"component service {service_index} external contract",
            )
        except CheckedExternalSiteContractError as exc:
            _issue(
                issues,
                "violated",
                "component_external_contract_malformed",
                service_index=service_index,
                detail=str(exc),
            )
            continue
        for event in _array(service.get("events", []), "component service events"):
            reference = _object(event, "component service event")
            unit_id = reference.get("unit_id")
            event_index = reference.get("index")
            if (
                reference.get("family") != "external_event"
                or not isinstance(unit_id, str)
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
            ):
                _issue(
                    issues,
                    "violated",
                    "component_external_event_reference_malformed",
                    service_index=service_index,
                )
                continue
            if reference.get("external_contract_id") != contract.contract_id:
                _issue(
                    issues,
                    "violated",
                    "component_external_contract_binding_stale",
                    service_index=service_index,
                    unit_id=unit_id,
                    event_index=event_index,
                )
                continue
            key = (unit_id, event_index)
            if key in result:
                _issue(
                    issues,
                    "violated",
                    "component_external_event_contract_duplicated",
                    unit_id=unit_id,
                    event_index=event_index,
                )
                continue
            result[key] = contract
    return result


def _external_call_payloads(
    members: Mapping[str, Mapping[str, object]],
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
) -> list[dict[str, object]]:
    return [
        {
            "unit_id": unit_id,
            "event_index": event_index,
            "contract": contract.payload(),
        }
        for (unit_id, event_index), contract in sorted(external_contracts.items())
        if unit_id in members
    ]


def _check_completion(
    value: object,
    interface: Mapping[str, object],
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
    issues: list[dict[str, object]],
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        _issue(issues, "incomplete", "component_completion_missing")
        return {}
    if set(value) != {"kind", "state", "memory_writes", "return_target"}:
        _issue(
            issues,
            "violated",
            "component_completion_fields_not_canonical",
            observed=sorted(str(key) for key in value),
        )
        return copy.deepcopy(dict(value))
    if value.get("kind") != "explicit-machine-state-v1":
        _issue(
            issues,
            "incomplete",
            "component_completion_kind_not_supported",
            observed=value.get("kind"),
        )
    state = value.get("state")
    if not isinstance(state, Mapping) or set(state) != set(_STATE_FIELDS):
        _issue(
            issues,
            "violated",
            "component_completion_state_not_total",
            expected=list(_STATE_FIELDS),
            observed=sorted(str(key) for key in state) if isinstance(state, Mapping) else state,
        )
    else:
        for field in _STATE_FIELDS:
            _check_completion_expression(
                state[field], interface, external_contracts, issues, f"state.{field}"
            )
    memory_writes = value.get("memory_writes")
    if not isinstance(memory_writes, list):
        _issue(
            issues,
            "violated",
            "component_completion_memory_writes_malformed",
            observed=memory_writes,
        )
    else:
        for index, raw in enumerate(memory_writes):
            location = f"memory_writes[{index}]"
            if not isinstance(raw, Mapping) or set(raw) != {
                "address",
                "value",
                "width",
            }:
                _issue(
                    issues,
                    "violated",
                    "component_completion_memory_write_malformed",
                    location=location,
                    observed=copy.deepcopy(raw),
                )
                continue
            if raw.get("width") not in {1, 2, 4} or isinstance(
                raw.get("width"), bool
            ):
                _issue(
                    issues,
                    "incomplete",
                    "component_completion_memory_write_width_not_supported",
                    location=f"{location}.width",
                    observed=raw.get("width"),
                )
            _check_completion_expression(
                raw.get("address"),
                interface,
                external_contracts,
                issues,
                f"{location}.address",
            )
            _check_completion_expression(
                raw.get("value"),
                interface,
                external_contracts,
                issues,
                f"{location}.value",
            )
    _check_completion_expression(
        value.get("return_target"),
        interface,
        external_contracts,
        issues,
        "return_target",
    )
    return copy.deepcopy(dict(value))


def _check_completion_expression(
    value: object,
    interface: Mapping[str, object],
    external_contracts: Mapping[tuple[str, int], CheckedExternalSiteContract],
    issues: list[dict[str, object]],
    location: str,
) -> None:
    if not isinstance(value, Mapping):
        _issue(
            issues,
            "violated",
            "component_completion_expression_malformed",
            location=location,
        )
        return
    op = value.get("op")
    if op not in _SUPPORTED_COMPLETION_OPS:
        _issue(
            issues,
            "incomplete",
            "component_completion_expression_not_supported",
            location=location,
            observed=op,
        )
        return
    if op == "entry" and value.get("name") not in _STATE_FIELDS:
        _issue(
            issues,
            "violated",
            "component_completion_entry_field_invalid",
            location=location,
            observed=value.get("name"),
        )
    if op == "logical_result":
        result_ids = {
            row.get("id")
            for row in _array(interface.get("results"), "logical results")
            if isinstance(row, Mapping) and row.get("kind") in {"return", "value"}
        }
        if value.get("result_id") not in result_ids:
            _issue(
                issues,
                "violated",
                "component_completion_result_invalid",
                location=location,
                observed=value.get("result_id"),
            )
    if op == "external_result":
        expected_fields = {"op", "unit_id", "event_index", "register"}
        if set(value) != expected_fields:
            _issue(
                issues,
                "violated",
                "component_completion_external_result_malformed",
                location=location,
                observed=sorted(str(key) for key in value),
            )
            return
        unit_id = value.get("unit_id")
        event_index = value.get("event_index")
        register = value.get("register")
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
            or register not in _STATE_FIELDS[:8]
        ):
            _issue(
                issues,
                "violated",
                "component_completion_external_result_malformed",
                location=location,
            )
            return
        contract = external_contracts.get((unit_id, event_index))
        if contract is None:
            _issue(
                issues,
                "violated",
                "component_completion_external_result_binding_stale",
                location=location,
                unit_id=unit_id,
                event_index=event_index,
            )
            return
        if not any(
            isinstance(relation, Mapping)
            and relation.get("register") == register
            and relation.get("relation") == "exact"
            for relation in contract.result_register_relations
        ):
            _issue(
                issues,
                "incomplete",
                "component_completion_external_result_not_exact",
                location=location,
                unit_id=unit_id,
                event_index=event_index,
                register=register,
                contract_id=contract.contract_id,
            )
    if op == "load":
        _check_completion_expression(
            value.get("address"),
            interface,
            external_contracts,
            issues,
            f"{location}.address",
        )
    for index, arg in enumerate(_array(value.get("args", []), "completion arguments")):
        if isinstance(arg, Mapping):
            _check_completion_expression(
                arg,
                interface,
                external_contracts,
                issues,
                f"{location}.args[{index}]",
            )


def _contract_entries(catalog: Mapping[str, object], identity: str) -> list[str]:
    matches = [
        _object(row, "component catalog row")
        for row in _array(catalog.get("components"), "component catalog")
        if isinstance(row, Mapping) and row.get("id") == identity
    ]
    if len(matches) != 1:
        raise ComponentIntentError(f"component catalog does not contain {identity}")
    boundary = _object(matches[0].get("machine_boundary"), "component boundary")
    return [
        _string(_object(row, "component entry").get("unit_id"), "component entry unit")
        for row in _array(boundary.get("entries"), "component entries")
    ]


def _is_stack_expression(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("op") == "reg" and value.get("name") in {"esp", "ebp"}:
        return True
    return any(
        _is_stack_expression(arg)
        for arg in value.get("args", [])
        if isinstance(arg, Mapping)
    ) or _is_stack_expression(value.get("address"))


def _load_machine_ir(
    root: Path,
) -> tuple[Path, Path, dict[str, Mapping[str, object]]]:
    machine_path = root / "machine-ir.jsonl" if root.is_dir() else root
    manifest_path = (
        root / "machine-ir-manifest.json"
        if root.is_dir()
        else root.parent / "machine-ir-manifest.json"
    )
    manifest = _read_object(manifest_path, "machine-IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise ComponentIntentError("unsupported machine-IR manifest format")
    artifact = _object(
        _object(manifest.get("artifacts"), "machine-IR artifacts").get("machine_ir"),
        "machine-IR artifact",
    )
    if artifact.get("sha256") != sha256_file(machine_path):
        raise ComponentIntentError("machine-IR artifact binding is stale")
    rows: dict[str, Mapping[str, object]] = {}
    for number, line in enumerate(machine_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = _object(json.loads(line), f"machine IR line {number}")
        identity = _string(row.get("id"), f"machine IR line {number} id")
        if identity in rows:
            raise ComponentIntentError(f"duplicate machine unit {identity}")
        rows[identity] = row
    return machine_path, manifest_path, rows


def _unit_rva(row: Mapping[str, object]) -> int:
    return int(
        _object(
            _object(row.get("source"), "machine unit source").get("original"),
            "machine unit original range",
        )["rva_start"]
    )


def _issue(
    issues: list[dict[str, object]], status: str, code: str, **details: object
) -> None:
    issues.append({"status": status, "code": code, **details})


def _read_object(path: Path, description: str) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc
    return dict(_object(raw, description))


def _check_self_hash(
    payload: Mapping[str, object],
    format_name: str,
    field: str,
    description: str,
) -> None:
    if payload.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    core = copy.deepcopy(dict(payload))
    expected = core.pop(field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")


def _canonical_sha256(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
    ).hexdigest()


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


__all__ = ["build_component_adapter_plan", "load_component_adapter_plan"]
