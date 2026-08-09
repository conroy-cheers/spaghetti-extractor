"""Hash-bound analysis contracts for internal machine-code functions.

These contracts are static analysis aids, not replacement authority.  The
machine-IR fallback continues to execute every exact decoded unit.  A reviewed
contract only supplies call-frame and result provenance that is otherwise
expensive or impractical to infer through an opaque linked runtime.
"""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from .stage_binary import StageAInputError


INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT = (
    "stage-a-internal-function-contract-profile-v1"
)
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"})


class InternalFunctionContractError(StageAInputError):
    """An internal function contract is malformed, stale, or ambiguous."""


def load_internal_function_contracts(
    paths: Sequence[Path],
    *,
    binary_sha256: str,
    units: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Load exact-unit-bound summary overrides keyed by entry unit ID."""

    by_id = {str(unit.get("id")): unit for unit in units}
    if len(by_id) != len(units):
        raise InternalFunctionContractError(
            "internal contracts require unique machine-IR unit IDs"
        )
    by_rva: dict[int, str] = {}
    for unit_id, unit in by_id.items():
        source = _mapping(unit.get("source"), f"machine-IR unit {unit_id} source")
        original = _mapping(
            source.get("original"), f"machine-IR unit {unit_id} original span"
        )
        rva = original.get("rva_start")
        if not isinstance(rva, int) or isinstance(rva, bool) or rva in by_rva:
            raise InternalFunctionContractError(
                "internal contracts require unique machine-IR unit RVAs"
            )
        by_rva[rva] = unit_id
    result: dict[str, dict[str, Any]] = {}
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InternalFunctionContractError(
                f"cannot load internal function profile {path}"
            ) from exc
        if not isinstance(payload, Mapping):
            raise InternalFunctionContractError(
                f"internal function profile {path} must be an object"
            )
        core = copy.deepcopy(dict(payload))
        observed_hash = core.pop("profile_sha256", None)
        if (
            core.get("format") != INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT
            or observed_hash != _canonical_sha256(core)
        ):
            raise InternalFunctionContractError(
                f"internal function profile {path} has a stale format or self-hash"
            )
        if core.get("binary_sha256") != binary_sha256:
            raise InternalFunctionContractError(
                f"internal function profile {path} targets a different PE"
            )
        contracts = core.get("contracts")
        if not isinstance(contracts, list):
            raise InternalFunctionContractError(
                f"internal function profile {path} has no contract inventory"
            )
        for index, raw in enumerate(contracts):
            context = f"internal function profile {path} contract {index}"
            if not isinstance(raw, Mapping):
                raise InternalFunctionContractError(f"{context} must be an object")
            unit_id = _string(raw.get("entry_unit_id"), f"{context} entry unit")
            unit = by_id.get(unit_id)
            if unit is None:
                raise InternalFunctionContractError(
                    f"{context} entry unit is absent from the machine IR"
                )
            source = _mapping(unit.get("source"), f"{context} source")
            original = _mapping(source.get("original"), f"{context} original span")
            if (
                raw.get("entry_rva") != original.get("rva_start")
                or raw.get("entry_contract_sha256") != source.get("contract_sha256")
                or raw.get("entry_instruction_bytes_sha256")
                != source.get("instruction_bytes_sha256")
            ):
                raise InternalFunctionContractError(
                    f"{context} entry binding is stale"
                )
            body = raw.get("body_units")
            if not isinstance(body, list) or not body:
                raise InternalFunctionContractError(
                    f"{context} requires a nonempty reviewed body-unit binding"
                )
            bound_ids: set[str] = set()
            for body_index, body_raw in enumerate(body):
                body_context = f"{context} body unit {body_index}"
                body_row = _mapping(body_raw, body_context)
                body_id = _string(body_row.get("unit_id"), f"{body_context} ID")
                body_unit = by_id.get(body_id)
                if body_unit is None or body_id in bound_ids:
                    raise InternalFunctionContractError(
                        f"{body_context} is absent or duplicated"
                    )
                bound_ids.add(body_id)
                body_source = _mapping(
                    body_unit.get("source"), f"{body_context} source"
                )
                if body_row.get("contract_sha256") != body_source.get(
                    "contract_sha256"
                ):
                    raise InternalFunctionContractError(
                        f"{body_context} binding is stale"
                    )
            if unit_id not in bound_ids:
                raise InternalFunctionContractError(
                    f"{context} body binding omits its entry unit"
                )
            expected_body = _normal_control_closure(unit_id, by_id=by_id, by_rva=by_rva)
            if bound_ids != expected_body:
                raise InternalFunctionContractError(
                    f"{context} body binding is not the exact normal-control closure"
                )
            summary = _normalize_summary(
                raw.get("summary"), context=context, contract_id=raw.get("id")
            )
            return_unit_ids = sorted(
                body_id
                for body_id in bound_ids
                if _unit_has_machine_return(by_id[body_id])
            )
            behavior = _mapping(
                summary.get("return_behavior"), f"{context} return behavior"
            )
            if bool(return_unit_ids) != behavior.get("may_return"):
                raise InternalFunctionContractError(
                    f"{context} return claim contradicts its exact decoded body"
                )
            summary.update({
                "reached_units": len(bound_ids),
                "return_nodes": len(return_unit_ids),
                "return_unit_ids": return_unit_ids,
                "nonreturning_nodes": (
                    1 if behavior.get("may_not_return") is True else 0
                ),
            })
            summary["declared_internal_contract"] = {
                "profile_id": _string(core.get("id"), f"{context} profile ID"),
                "profile_sha256": observed_hash,
                "contract_id": _string(raw.get("id"), f"{context} contract ID"),
                "binary_sha256": binary_sha256,
                "entry_unit_id": unit_id,
                "entry_rva": original.get("rva_start"),
                "entry_contract_sha256": source.get("contract_sha256"),
                "entry_instruction_bytes_sha256": source.get(
                    "instruction_bytes_sha256"
                ),
                "body_unit_count": len(bound_ids),
                "body_units": [
                    {
                        "unit_id": body_id,
                        "contract_sha256": _mapping(
                            by_id[body_id].get("source"),
                            f"{context} body source",
                        ).get("contract_sha256"),
                    }
                    for body_id in sorted(bound_ids)
                ],
                "authority": "operator_reviewed_static_analysis_assumption",
                "replacement_authority": False,
            }
            if unit_id in result and result[unit_id] != summary:
                raise InternalFunctionContractError(
                    f"internal function contract for {unit_id} is ambiguous"
                )
            result[unit_id] = summary
    return result


def bind_internal_function_contract_profile(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a canonical self-hashed profile for target-intent tooling."""

    core = copy.deepcopy(dict(payload))
    core.pop("profile_sha256", None)
    if core.get("format") != INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT:
        raise InternalFunctionContractError("unsupported internal function profile format")
    return {**core, "profile_sha256": _canonical_sha256(core)}


def rebind_internal_function_contract_profile(
    payload: Mapping[str, Any],
    *,
    binary_sha256: str,
    units: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Rebind reviewed summaries after semantics-only machine-IR changes.

    The binary bytes, entry instruction bytes, entry RVA, and exact body-unit
    closure must remain unchanged. Only derived semantic contract hashes are
    refreshed; the operator-authored summaries are preserved verbatim.
    """

    core = copy.deepcopy(dict(payload))
    observed_hash = core.pop("profile_sha256", None)
    if (
        core.get("format") != INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT
        or observed_hash != _canonical_sha256(core)
        or core.get("binary_sha256") != binary_sha256
    ):
        raise InternalFunctionContractError(
            "internal function profile cannot be rebound from stale identity data"
        )
    by_id = {str(unit.get("id")): unit for unit in units}
    if len(by_id) != len(units):
        raise InternalFunctionContractError(
            "internal contract rebinding requires unique machine-IR unit IDs"
        )
    by_rva: dict[int, str] = {}
    for unit_id, unit in by_id.items():
        source = _mapping(unit.get("source"), f"machine-IR unit {unit_id} source")
        original = _mapping(
            source.get("original"), f"machine-IR unit {unit_id} original span"
        )
        rva = original.get("rva_start")
        if not isinstance(rva, int) or isinstance(rva, bool) or rva in by_rva:
            raise InternalFunctionContractError(
                "internal contract rebinding requires unique unit RVAs"
            )
        by_rva[rva] = unit_id

    contracts = core.get("contracts")
    if not isinstance(contracts, list):
        raise InternalFunctionContractError(
            "internal function profile has no contract inventory"
        )
    for index, raw in enumerate(contracts):
        context = f"internal function profile contract {index}"
        contract = _mapping(raw, context)
        entry_id = _string(contract.get("entry_unit_id"), f"{context} entry unit")
        entry = by_id.get(entry_id)
        if entry is None:
            raise InternalFunctionContractError(f"{context} entry unit is absent")
        entry_source = _mapping(entry.get("source"), f"{context} entry source")
        original = _mapping(entry_source.get("original"), f"{context} entry span")
        if (
            contract.get("entry_rva") != original.get("rva_start")
            or contract.get("entry_instruction_bytes_sha256")
            != entry_source.get("instruction_bytes_sha256")
        ):
            raise InternalFunctionContractError(
                f"{context} changed bytes or entry location and requires review"
            )
        body = contract.get("body_units")
        if not isinstance(body, list) or not body:
            raise InternalFunctionContractError(f"{context} body is missing")
        submitted_ids = {
            _string(_mapping(row, f"{context} body unit").get("unit_id"), f"{context} body unit ID")
            for row in body
        }
        expected_ids = _normal_control_closure(entry_id, by_id=by_id, by_rva=by_rva)
        if submitted_ids != expected_ids or len(submitted_ids) != len(body):
            raise InternalFunctionContractError(
                f"{context} control closure changed and requires review"
            )
        assert isinstance(raw, dict)
        raw["entry_contract_sha256"] = entry_source.get("contract_sha256")
        raw["body_units"] = [
            {
                "unit_id": unit_id,
                "contract_sha256": _mapping(
                    by_id[unit_id].get("source"), f"{context} body source"
                ).get("contract_sha256"),
            }
            for unit_id in sorted(expected_ids)
        ]
    return bind_internal_function_contract_profile(core)


def _normalize_summary(
    value: Any, *, context: str, contract_id: Any
) -> dict[str, Any]:
    summary = _mapping(value, f"{context} summary")
    preserved = summary.get("preserved_registers")
    if (
        not isinstance(preserved, list)
        or len(preserved) != len(set(preserved))
        or any(register not in _REGISTERS for register in preserved)
    ):
        raise InternalFunctionContractError(
            f"{context} has invalid preserved registers"
        )
    stack_cleanup = summary.get("stack_cleanup")
    raw_transform = summary.get("stack_transform")
    if stack_cleanup is not None and raw_transform is not None:
        raise InternalFunctionContractError(
            f"{context} cannot declare two stack transforms"
        )
    if raw_transform is None:
        if (
            not isinstance(stack_cleanup, int)
            or isinstance(stack_cleanup, bool)
            or not 0 <= stack_cleanup <= 0x10000
            or stack_cleanup % 4
        ):
            raise InternalFunctionContractError(
                f"{context} has invalid stack cleanup"
            )
        normalized_transform = {
            "format": "stage-a-affine-stack-transform-v1",
            "constant": stack_cleanup,
            "register_terms": [],
        }
    else:
        transform = _mapping(raw_transform, f"{context} stack transform")
        if transform.get("format") != "stage-a-affine-stack-transform-v1":
            raise InternalFunctionContractError(
                f"{context} has an unsupported stack transform"
            )
        constant = transform.get("constant")
        raw_terms = transform.get("register_terms")
        if (
            not isinstance(constant, int)
            or isinstance(constant, bool)
            or not isinstance(raw_terms, list)
            or not raw_terms
        ):
            raise InternalFunctionContractError(
                f"{context} has an invalid affine stack transform"
            )
        terms: dict[str, int] = {}
        for raw_term in raw_terms:
            term = _mapping(raw_term, f"{context} stack-transform term")
            register = term.get("register")
            coefficient = term.get("coefficient")
            if (
                register not in _REGISTERS
                or register == "esp"
                or not isinstance(coefficient, int)
                or isinstance(coefficient, bool)
                or coefficient == 0
                or abs(coefficient) > 16
                or register in terms
            ):
                raise InternalFunctionContractError(
                    f"{context} has an invalid affine stack-transform term"
                )
            terms[str(register)] = coefficient
        normalized_transform = {
            "format": "stage-a-affine-stack-transform-v1",
            "constant": constant,
            "register_terms": [
                {"register": register, "coefficient": terms[register]}
                for register in sorted(terms)
            ],
        }
    may_return = summary.get("may_return")
    may_not_return = summary.get("may_not_return")
    if not isinstance(may_return, bool) or not isinstance(may_not_return, bool):
        raise InternalFunctionContractError(
            f"{context} has incomplete return behavior"
        )
    raw_results = summary.get("result_register_origins", {})
    if not isinstance(raw_results, Mapping):
        raise InternalFunctionContractError(
            f"{context} result origins must be an object"
        )
    results: dict[str, dict[str, Any]] = {}
    for register, raw_origin in raw_results.items():
        if register not in _REGISTERS or not isinstance(raw_origin, Mapping):
            raise InternalFunctionContractError(
                f"{context} has an invalid result-register origin"
            )
        relation = raw_origin.get("relation")
        nullable = raw_origin.get("nullable")
        if relation != "dynamic_range_base" or not isinstance(nullable, bool):
            raise InternalFunctionContractError(
                f"{context} has an unsupported result-register relation"
            )
        results[str(register)] = {
            "kind": "internal_contract_result",
            "contract_id": _string(contract_id, f"{context} contract ID"),
            "relation": "dynamic_range_base",
            "nullable": nullable,
        }
    return {
        "status": "complete",
        "preserved_registers": sorted(preserved),
        "register_preservation": {"status": "complete"},
        "result_register_origins": {
            "status": "complete",
            "registers": results,
        },
        "stack_cleanup": {
            "status": "complete",
            "stack_delta": (
                normalized_transform["constant"]
                if not normalized_transform["register_terms"]
                else None
            ),
            "return_stack_offset": (
                normalized_transform["constant"] + 4
                if not normalized_transform["register_terms"]
                else None
            ),
            "transform": normalized_transform,
        },
        "return_behavior": {
            "status": "complete",
            "may_return": may_return,
            "may_not_return": may_not_return,
        },
        "reached_units": 0,
        "transfer_evaluations": 0,
        "return_nodes": 0,
        "return_unit_ids": [],
        "nonreturning_nodes": 0,
        "blocker_codes": [],
    }


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InternalFunctionContractError(f"{context} must be an object")
    return value


def _normal_control_closure(
    root: str,
    *,
    by_id: Mapping[str, Mapping[str, Any]],
    by_rva: Mapping[int, str],
) -> set[str]:
    reached = {root}
    pending = [root]
    while pending:
        unit_id = pending.pop()
        control = _mapping(
            by_id[unit_id].get("control", {}),
            f"machine-IR unit {unit_id} control",
        )
        targets = control.get("direct_targets", [])
        if not isinstance(targets, list):
            raise InternalFunctionContractError(
                f"machine-IR unit {unit_id} has malformed direct targets"
            )
        for target_rva in targets:
            if not isinstance(target_rva, int) or isinstance(target_rva, bool):
                raise InternalFunctionContractError(
                    f"machine-IR unit {unit_id} has an invalid direct target"
                )
            target_id = by_rva.get(target_rva)
            if target_id is None:
                raise InternalFunctionContractError(
                    f"machine-IR unit {unit_id} has an unresolved direct target"
                )
            if target_id not in reached:
                reached.add(target_id)
                pending.append(target_id)
    return reached


def _unit_has_machine_return(unit: Mapping[str, Any]) -> bool:
    semantics = _mapping(unit.get("semantics", {}), "machine-IR unit semantics")
    outcome = _mapping(semantics.get("outcome", {}), "machine-IR unit outcome")
    return outcome.get("kind") == "return"


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InternalFunctionContractError(f"{context} must be a nonempty string")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "INTERNAL_FUNCTION_CONTRACT_PROFILE_FORMAT",
    "InternalFunctionContractError",
    "bind_internal_function_contract_profile",
    "load_internal_function_contracts",
    "rebind_internal_function_contract_profile",
]
