from __future__ import annotations

import json
from typing import Any

from ...stage_binary import StageABinary
from ...util import sha256_bytes
from ..callsite_preservation import (
    CALLSITE_PRESERVATION_ARTIFACT_FORMAT,
    parse_callsite_preservation_artifact,
    serialize_callsite_preservation_artifact,
)
from ..contract import _semantic_expr_is_pure
from ..extraction import (
    _semantic_exact_memory_inputs,
)
from ..model import _semantic_constant_bool
from ..schema import STAGE_A_RELATIONAL_MODEL_ID
from .callsite import (
    CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
    propose_callsite_preserved_register_summary,
)
from .control import _constant_read32_address
from .dataflow import strongly_connected_components
from .external import _semantic_external_target_identity
from .invariants import _semantic_edges
from .region_local import (
    _attach_assembled_immutable_read_address_separations,
    _attach_import_seed_address_separations,
    _exact_index_expression,
    _iat_import_register_seed_candidates,
    _iat_seed_read,
    _refine_contract_bounds,
    _semantic_index_from_address,
    _semantic_read_addresses,
)
from .register_static import (
    _immutable_image_u32_value,
    _immutable_image_word_read,
    _paired_constant_relation,
)
from .segments import _semantic_expr_registers
from .stack import (
    _attach_return_slot_contracts,
    _direct_call_push_claim,
    _discover_static_call_return_summaries,
    _indirect_call_push_claim,
    _return_pop_claim,
)


_REGISTER_RELATION_KINDS = {
    "exact", "fixed_word", "code_pointer", "data_pointer", "fixed_code_pointer",
    "related_word",
}
RegisterRelation = str | dict[str, Any]
_X86_GENERAL_REGISTERS = frozenset({
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
})
_PE32_EXTERNAL_REGISTER_POLICY_ID = "win32-cdecl-stdcall-registers-v1"
_PE32_EXTERNAL_PRESERVED_REGISTERS = frozenset({
    "ebx", "esi", "edi", "ebp", "esp",
})
def _machine_result_invariant_relation(relation: dict[str, Any]) -> str:
    return "exact" if relation.get("relation") == "exact" else "related_word"


def _register_relation_kind(relation: RegisterRelation) -> str:
    if isinstance(relation, str):
        return relation
    return str(relation.get("relation", "related_word"))


def _register_relation_payload(relation: RegisterRelation) -> dict[str, Any]:
    kind = _register_relation_kind(relation)
    if kind == "fixed_word" and isinstance(relation, dict):
        value = relation.get("value")
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < 2**32
        ):
            return {"relation": kind, "value": int(value)}
    if kind == "fixed_code_pointer" and isinstance(relation, dict):
        target_id = relation.get("target_id")
        if (
            isinstance(target_id, int)
            and not isinstance(target_id, bool)
            and target_id >= 0
        ):
            return {"relation": kind, "target_id": int(target_id)}
    if kind in _REGISTER_RELATION_KINDS - {"fixed_word", "fixed_code_pointer"}:
        return {"relation": kind}
    return {"relation": "related_word"}


def _register_relation_key(relation: RegisterRelation) -> tuple[str, int | None]:
    payload = _register_relation_payload(relation)
    return payload["relation"], payload.get("target_id", payload.get("value"))


def _register_relation_join(relations: list[RegisterRelation]) -> RegisterRelation:
    if not relations:
        return "related_word"
    keys = {_register_relation_key(relation) for relation in relations}
    if len(keys) != 1:
        if all(
            _register_relation_kind(relation) in {"fixed_word", "exact"}
            for relation in relations
        ):
            return "exact"
        # In particular, fixed targets with different canonical IDs must never
        # retain either target identity after a join.
        return "related_word"
    if _register_relation_kind(relations[0]) in {
        "fixed_word", "fixed_code_pointer",
    }:
        return _register_relation_payload(relations[0])
    return _register_relation_kind(relations[0])


def _register_relation_implies(
    source: RegisterRelation, target: RegisterRelation,
) -> bool:
    source_key = _register_relation_key(source)
    target_key = _register_relation_key(target)
    if source_key == target_key or target_key[0] == "related_word":
        return True
    if source_key[0] == "fixed_word" and target_key[0] == "exact":
        return True
    return source_key[0] == "fixed_code_pointer" and target_key[0] == "code_pointer"


def _register_relation_implies_exact(relation: RegisterRelation) -> bool:
    return _register_relation_kind(relation) in {"exact", "fixed_word"}

def _fixed_register_values(
    input_relations: dict[str, RegisterRelation],
    candidate_registers: dict[str, str] | None,
) -> tuple[dict[str, int], dict[str, int]]:
    """Return unambiguous fixed scalar inputs for each binary side."""
    original_values: dict[str, int] = {}
    candidate_rows: dict[str, list[int]] = {}
    for original_register, relation in input_relations.items():
        payload = _register_relation_payload(relation)
        if payload["relation"] != "fixed_word":
            continue
        value = int(payload["value"]) & 0xFFFFFFFF
        original_values[str(original_register)] = value
        candidate_register = str(
            (candidate_registers or {}).get(
                str(original_register), str(original_register),
            )
        )
        candidate_rows.setdefault(candidate_register, []).append(value)
    candidate_values = {
        register: values[0]
        for register, values in candidate_rows.items()
        if len(values) == 1
    }
    return original_values, candidate_values


def _fixed_immutable_expr_value(
    expression: Any,
    binary: StageABinary,
    fixed_registers: dict[str, int],
) -> int | None:
    """Propose a value for the fragment replayed by Lean.

    This result never serves as proof evidence.  The generated claim includes
    only the proposed scalar; Lean reevaluates the decoded expression from the
    exact PE bytes and checked source invariant.
    """
    if not isinstance(expression, dict):
        return None
    operation = str(expression.get("op", ""))
    mask = 0xFFFFFFFF

    if operation == "input_reg":
        value = fixed_registers.get(str(expression.get("reg", "")))
        return None if value is None else value & mask
    if operation == "constant":
        value = expression.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        return value & mask

    if operation in {
        "add", "sub", "bit_and", "bit_xor", "bit_or", "multiply",
        "multiply_high_unsigned", "multiply_high_signed",
        "shift_left_by", "shift_right_by", "shift_arithmetic_right_by",
        "unsigned_less_value",
    }:
        left = _fixed_immutable_expr_value(
            expression.get("left"), binary, fixed_registers,
        )
        right = _fixed_immutable_expr_value(
            expression.get("right"), binary, fixed_registers,
        )
        if left is None or right is None:
            return None
        if operation == "add":
            return (left + right) & mask
        if operation == "sub":
            return (left - right) & mask
        if operation == "bit_and":
            return left & right
        if operation == "bit_xor":
            return left ^ right
        if operation == "bit_or":
            return left | right
        if operation == "multiply":
            return (left * right) & mask
        if operation == "multiply_high_unsigned":
            return ((left * right) >> 32) & mask
        if operation == "multiply_high_signed":
            signed_left = left if left < 0x80000000 else left - 0x100000000
            signed_right = right if right < 0x80000000 else right - 0x100000000
            return ((signed_left * signed_right) >> 32) & mask
        if operation == "shift_left_by":
            return (left << (right % 32)) & mask
        if operation == "shift_right_by":
            return left >> (right % 32)
        if operation == "shift_arithmetic_right_by":
            signed = left if left < 0x80000000 else left - 0x100000000
            return (signed >> (right % 32)) & mask
        return 1 if left < right else 0

    if operation in {"bit_not", "lowest_set_bit", "highest_set_bit"}:
        value = _fixed_immutable_expr_value(
            expression.get("value"), binary, fixed_registers,
        )
        if value is None:
            return None
        if operation == "bit_not":
            return (~value) & mask
        if operation == "lowest_set_bit":
            return 32 if value == 0 else (value & -value).bit_length() - 1
        return 0 if value == 0 else value.bit_length() - 1

    if operation in {"shift_left", "shift_right"}:
        value = _fixed_immutable_expr_value(
            expression.get("value"), binary, fixed_registers,
        )
        amount = expression.get("amount")
        if (
            value is None
            or not isinstance(amount, int)
            or isinstance(amount, bool)
            or amount < 0
        ):
            return None
        if operation == "shift_left":
            return (value << amount) & mask if amount < 32 else 0
        return value >> amount if amount < 32 else 0

    if operation in {"extract_byte", "bit_value"}:
        value = _fixed_immutable_expr_value(
            expression.get("value"), binary, fixed_registers,
        )
        index = expression.get("index")
        if (
            value is None
            or not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
        ):
            return None
        if operation == "extract_byte":
            return (value >> (index * 8)) & 0xFF if index < 4 else 0
        return (value >> index) & 1 if index < 32 else 0

    if operation in {"read8", "read32"}:
        address = _fixed_immutable_expr_value(
            expression.get("address"), binary, fixed_registers,
        )
        if address is None:
            return None
        word = _immutable_image_u32_value(binary, address)
        if word is None:
            return None
        return word & 0xFF if operation == "read8" else word

    if operation == "if_equal":
        left = _fixed_immutable_expr_value(
            expression.get("left"), binary, fixed_registers,
        )
        right = _fixed_immutable_expr_value(
            expression.get("right"), binary, fixed_registers,
        )
        if left is None or right is None:
            return None
        branch = expression.get("then" if left == right else "else")
        return _fixed_immutable_expr_value(branch, binary, fixed_registers)

    return None

def _infer_register_output_relation(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    input_relations: dict[str, RegisterRelation],
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    global_values_empty: bool,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
    candidate_input_registers: dict[str, str] | None = None,
) -> tuple[RegisterRelation, str]:
    constant_relation = _paired_constant_relation(
        original_expression,
        candidate_expression,
        contract,
        original_image_base,
        candidate_image_base,
    )
    if constant_relation is not None:
        return constant_relation, "paired_constant"
    static_slot = _matching_static_word_relation_slot(
        original_expression, candidate_expression, contract,
    )
    if static_slot is not None:
        relation = str(static_slot["relation"])
        if relation == "fixed_code_pointer":
            relation = {
                "relation": "fixed_code_pointer",
                "target_id": int(static_slot["target_id"]),
            }
        return relation, "static_word_slot"
    if (
        original_bin is not None
        and candidate_bin is not None
    ):
        original_read = _immutable_image_word_read(
            original_expression, original_bin,
        )
        candidate_read = _immutable_image_word_read(
            candidate_expression, candidate_bin,
        )
        if original_read is not None and candidate_read is not None:
            _, original_writes, original_assembled, original_value = original_read
            _, candidate_writes, candidate_assembled, candidate_value = candidate_read
            immutable_relation = _paired_constant_relation(
                {"op": "constant", "value": original_value},
                {"op": "constant", "value": candidate_value},
                contract,
                original_image_base,
                candidate_image_base,
            )
            if immutable_relation is not None:
                if not original_assembled and not candidate_assembled:
                    return immutable_relation, "immutable_image_word"
                if (
                    original_assembled == candidate_assembled
                    and len(original_writes) == len(candidate_writes)
                ):
                    return immutable_relation, "assembled_immutable_image_word"
    if (
        original_expression.get("op") == "input_reg"
        and candidate_expression.get("op") == "input_reg"
    ):
        register = str(original_expression.get("reg"))
        candidate_register = str(candidate_expression.get("reg"))
        expected_candidate = (candidate_input_registers or {}).get(
            register, register,
        )
        if candidate_register == expected_candidate:
            return (
                input_relations.get(register, "related_word"),
                "identity_transfer",
            )
    if original_bin is not None and candidate_bin is not None:
        original_fixed, candidate_fixed = _fixed_register_values(
            input_relations, candidate_input_registers,
        )
        original_value = _fixed_immutable_expr_value(
            original_expression, original_bin, original_fixed,
        )
        candidate_value = _fixed_immutable_expr_value(
            candidate_expression, candidate_bin, candidate_fixed,
        )
        if original_value is not None and candidate_value is not None:
            fixed_relation = _paired_constant_relation(
                {"op": "constant", "value": original_value},
                {"op": "constant", "value": candidate_value},
                contract,
                original_image_base,
                candidate_image_base,
            )
            if fixed_relation is not None:
                return fixed_relation, "fixed_immutable_expression"
    if original_expression == candidate_expression:
        dependencies = _semantic_expr_registers(original_expression)
        if _semantic_expr_is_pure(original_expression) and all(
            _register_relation_implies_exact(
                input_relations.get(register, "related_word")
            )
            for register in dependencies
        ):
            return "exact", "lean_exact_memory_free_expression"
        if global_values_empty and _semantic_exact_memory_inputs(
            original_expression,
            {
                register for register, relation in input_relations.items()
                if _register_relation_implies_exact(relation)
            },
        ):
            return "exact", "lean_exact_memory_expression"
    return "related_word", "unsupported_or_mixed_relation"


def _matching_static_word_relation_slot(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any] | None:
    original_address = _constant_read32_address(original_expression)
    candidate_address = _constant_read32_address(candidate_expression)
    if original_address is None or candidate_address is None:
        return None
    code_targets = contract.get("code_targets", [])
    matches = []
    for slot in contract.get("static_word_relation_slots", []):
        if not isinstance(slot, dict):
            continue
        relation = str(slot.get("relation"))
        valid_fixed_target = False
        if relation == "fixed_code_pointer":
            target_id = slot.get("target_id")
            valid_fixed_target = (
                isinstance(target_id, int)
                and not isinstance(target_id, bool)
                and target_id >= 0
                and isinstance(code_targets, list)
                and target_id < len(code_targets)
                and isinstance(code_targets[target_id], dict)
                and code_targets[target_id].get("id") == target_id
            )
        if (
            int(slot.get("original_address", -1)) == original_address
            and int(slot.get("candidate_address", -1)) == candidate_address
            and (
                relation in _REGISTER_RELATION_KINDS - {"fixed_code_pointer"}
                or valid_fixed_target
            )
        ):
            matches.append(slot)
    return dict(matches[0]) if len(matches) == 1 else None

def _callsite_generation_incomplete(
    callsite: int,
    code: str,
    *,
    node_id: int | None = None,
    reference: Any = None,
    nested_reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    issue: dict[str, Any] = {"code": code}
    if node_id is not None:
        issue["node_id"] = int(node_id)
    if reference is not None:
        issue["reference"] = reference
    if nested_reason_codes:
        issue["nested_reason_codes"] = sorted(set(nested_reason_codes))
    return {
        "format": CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
        "status": "incomplete",
        "callsite_id": int(callsite),
        "reason_codes": [code],
        "issues": [issue],
        "certificate": None,
    }


def _translate_callsite_behavior(
    behavior: dict[str, Any],
    region_by_target_id: dict[int, int],
) -> tuple[dict[str, Any], list[str]]:
    translated = json.loads(json.dumps(behavior))
    outcome = translated.get("outcome")
    if not isinstance(outcome, dict):
        return translated, ["normalized_outcome_missing"]
    operation = outcome.get("op")
    target_fields: tuple[str, ...]
    if operation == "jump":
        target_fields = ("target",)
    elif operation == "branch":
        target_fields = ("taken", "fallthrough")
    elif operation == "call":
        target_fields = ("target", "continuation")
    elif operation == "call_unmapped_return":
        target_fields = ("target",)
    elif operation == "external_call":
        target_fields = ("continuation",)
    elif operation == "indirect_call":
        target_fields = ("continuation",)
    else:
        target_fields = ()
    issues: list[str] = []
    for field in target_fields:
        target_id = outcome.get(field)
        if (
            not isinstance(target_id, int)
            or isinstance(target_id, bool)
            or int(target_id) not in region_by_target_id
        ):
            issues.append(f"{field}_target_unmapped")
            continue
        outcome[field] = region_by_target_id[int(target_id)]
    return translated, sorted(set(issues))


def _propose_internal_callsite_preservation_summaries(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    import_register_analysis: dict[str, Any],
    register_relations: dict[str, Any],
) -> dict[str, Any]:
    """Propose callsite-local preservation without granting proof authority.

    Static return summaries delimit each callee and its exact return inventory.
    Normalized control targets are converted to paired region indices, then the
    standalone analyzer checks syntactic register preservation over that finite
    graph.  Every result remains untrusted until generated Lean replays it.
    """
    regions = contract.get("regions", [])
    duplicate_target_ids: set[int] = set()
    region_by_target_id: dict[int, int] = {}
    for region_index, region in enumerate(regions):
        target_id = region.get("numeric_id")
        if not isinstance(target_id, int) or isinstance(target_id, bool):
            continue
        if int(target_id) in region_by_target_id:
            duplicate_target_ids.add(int(target_id))
            continue
        region_by_target_id[int(target_id)] = region_index
    for target_id in duplicate_target_ids:
        region_by_target_id.pop(target_id, None)

    relations_by_callsite: dict[int, list[dict[str, Any]]] = {}
    for inventory in ("relations", "callsite_candidate_relations"):
        for row in import_register_analysis.get(inventory, []):
            try:
                callsite = int(row["region_index"])
                relation = {
                    "original": str(row["original_register"]),
                    "candidate": str(row["candidate_register"]),
                    "import": json.loads(json.dumps(row["import"])),
                }
            except (KeyError, TypeError, ValueError):
                continue
            if not 0 <= callsite < len(behaviors):
                continue
            relations_by_callsite.setdefault(callsite, []).append(relation)
    for callsite, relations in relations_by_callsite.items():
        relations_by_callsite[callsite] = sorted(
            {
                json.dumps(relation, sort_keys=True, separators=(",", ":")):
                    relation
                for relation in relations
            }.values(),
            key=lambda relation: json.dumps(
                relation, sort_keys=True, separators=(",", ":")
            ),
        )

    register_relations_by_callsite: dict[int, list[dict[str, Any]]] = {}
    relation_rows = register_relations.get("regions", [])
    for callsite, row in enumerate(relation_rows):
        if not isinstance(row, dict):
            continue
        for claim_index, claim in enumerate(row.get("output_claims", [])):
            if not isinstance(claim, dict) or not isinstance(claim.get("output"), dict):
                continue
            output = claim["output"]
            relation_kind = output.get("relation")
            if relation_kind not in {
                "fixed_word", "code_pointer", "fixed_code_pointer", "data_pointer",
            }:
                continue
            pair = (str(output.get("original")), str(output.get("candidate")))
            if pair[0] not in _X86_GENERAL_REGISTERS or pair[1] not in (
                _X86_GENERAL_REGISTERS
            ):
                continue
            relation = json.loads(json.dumps(output))
            relation["origin"] = {
                "kind": "region_output_claim",
                "region_index": callsite,
                "claim_index": claim_index,
                "claim_hash": sha256_bytes(json.dumps(
                    claim, sort_keys=True, separators=(",", ":"), allow_nan=False,
                ).encode()),
            }
            register_relations_by_callsite.setdefault(callsite, []).append(relation)
    for callsite, relations in register_relations_by_callsite.items():
        register_relations_by_callsite[callsite] = sorted(
            {
                json.dumps(relation, sort_keys=True, separators=(",", ":")):
                    relation
                for relation in relations
            }.values(),
            key=lambda relation: json.dumps(
                relation, sort_keys=True, separators=(",", ":")
            ),
        )

    raw_summaries = (
        register_relations.get("return_slot_analysis", {})
        .get("call_summary_analysis", {})
        .get("summaries", [])
    )
    summaries_by_callsite: dict[int, list[dict[str, Any]]] = {}
    duplicate_callsites: set[int] = set()
    for summary in raw_summaries:
        if not isinstance(summary, dict):
            continue
        try:
            callsite = int(summary["callsite_region_index"])
        except (KeyError, TypeError, ValueError):
            continue
        summaries_by_callsite.setdefault(callsite, []).append(summary)
    summary_by_callsite = {
        callsite: sorted(
            summaries,
            key=lambda summary: json.dumps(
                summary, sort_keys=True, separators=(",", ":")
            ),
        )[0]
        for callsite, summaries in summaries_by_callsite.items()
    }
    duplicate_callsites.update(
        callsite for callsite, summaries in summaries_by_callsite.items()
        if len(summaries) != 1
    )

    translated_behaviors: list[dict[str, Any]] = []
    translation_issues: dict[int, list[str]] = {}
    for region_index, behavior_pair in enumerate(behaviors):
        original, original_issues = _translate_callsite_behavior(
            behavior_pair.get("original_ir") or {}, region_by_target_id
        )
        candidate, candidate_issues = _translate_callsite_behavior(
            behavior_pair.get("candidate_ir") or {}, region_by_target_id
        )
        translated_behaviors.append({
            "node_id": region_index,
            "original_ir": original,
            "candidate_ir": candidate,
        })
        issues = sorted(set(original_issues + candidate_issues))
        if issues:
            translation_issues[region_index] = issues

    base_control: list[dict[str, Any]] = []
    returning_external_contracts: dict[tuple[int, int], dict[str, Any]] = {}
    direct_external_contracts: dict[int, dict[str, Any]] = {}
    ambiguous_direct_external_sources: set[int] = set()
    known_indirect_calls: dict[int, tuple[int, int]] = {}
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and not isinstance(item.get("id"), bool)
    }
    for edge in register_relations.get("edges", []):
        if not isinstance(edge, dict):
            continue
        direct_contract_id = edge.get("machine_contract_id")
        direct_source = edge.get("source_region_index")
        if (
            edge.get("kind") == "external_call"
            and isinstance(direct_contract_id, int)
            and not isinstance(direct_contract_id, bool)
            and isinstance(direct_source, int)
            and not isinstance(direct_source, bool)
            and int(direct_contract_id) in contracts_by_id
        ):
            source_id = int(direct_source)
            contract_row = contracts_by_id[int(direct_contract_id)]
            existing = direct_external_contracts.get(source_id)
            if existing is not None and existing != contract_row:
                ambiguous_direct_external_sources.add(source_id)
                direct_external_contracts.pop(source_id, None)
            elif source_id not in ambiguous_direct_external_sources:
                direct_external_contracts[source_id] = contract_row
        indirect_claim = edge.get("indirect_target_claim")
        if (
            edge.get("kind") == "call"
            and isinstance(indirect_claim, dict)
            and isinstance(edge.get("source_region_index"), int)
            and isinstance(edge.get("target_region_index"), int)
            and isinstance(indirect_claim.get("continuation_region_index"), int)
        ):
            known_indirect_calls[int(edge["source_region_index"])] = (
                int(edge["target_region_index"]),
                int(indirect_claim["continuation_region_index"]),
            )
        contract_id = edge.get("returning_external_thunk_contract_id")
        if not isinstance(contract_id, int) or isinstance(contract_id, bool):
            continue
        machine_contract = contracts_by_id.get(int(contract_id))
        if machine_contract is None:
            continue
        returning_external_contracts[(
            int(edge["source_region_index"]),
            int(edge["target_region_index"]),
        )] = machine_contract
    for region_index, behavior_pair in enumerate(translated_behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_op = original_outcome.get("op")
        candidate_op = candidate_outcome.get("op")
        successors: list[int] = []
        exit_row: dict[str, Any]
        if original_op != candidate_op:
            exit_row = {"kind": "unsupported"}
        elif original_op == "jump" and isinstance(original_outcome.get("target"), int):
            successors = [int(original_outcome["target"])]
            exit_row = {"kind": "direct"}
        elif original_op == "branch" and all(
            isinstance(original_outcome.get(field), int)
            for field in ("taken", "fallthrough")
        ):
            successors = [
                int(original_outcome["taken"]),
                int(original_outcome["fallthrough"]),
            ]
            exit_row = {"kind": "direct"}
        elif original_op == "returned":
            exit_row = {"kind": "return"}
        elif original_op == "call" and all(
            isinstance(original_outcome.get(field), int)
            for field in ("target", "continuation")
        ):
            successors = [int(original_outcome["continuation"])]
            machine_contract = returning_external_contracts.get((
                region_index, int(original_outcome["target"]),
            ))
            if machine_contract is None:
                exit_row = {"kind": "nested_call"}
            else:
                preserved = sorted({
                    str(register)
                    for register in machine_contract.get("preserved_registers", [])
                    if str(register) in _X86_GENERAL_REGISTERS
                })
                exit_row = {
                    "kind": "external_call",
                    "machine_contract_id": int(machine_contract["id"]),
                    "original_preserved_registers": preserved,
                    "candidate_preserved_registers": preserved,
                }
        elif original_op == "external_call" and all(
            isinstance(original_outcome.get(field), int)
            and isinstance(candidate_outcome.get(field), int)
            for field in ("continuation",)
        ):
            machine_contract = direct_external_contracts.get(region_index)
            if (
                machine_contract is None
                or machine_contract.get("disposition") != "returns"
                or original_outcome.get("continuation")
                    != candidate_outcome.get("continuation")
                or _semantic_external_target_identity(
                    original_outcome.get("import")
                ) != _semantic_external_target_identity(
                    candidate_outcome.get("import")
                )
            ):
                exit_row = {"kind": "unsupported"}
            else:
                preserved = sorted({
                    str(register)
                    for register in machine_contract.get(
                        "preserved_registers", []
                    )
                    if str(register) in _X86_GENERAL_REGISTERS
                })
                successors = [int(original_outcome["continuation"])]
                exit_row = {
                    "kind": "external_call",
                    "machine_contract_id": int(machine_contract["id"]),
                    "original_preserved_registers": preserved,
                    "candidate_preserved_registers": preserved,
                }
        elif original_op in {"indirect_call", "indirect_jump"}:
            exit_row = {"kind": "unresolved_indirect"}
        else:
            exit_row = {"kind": "unsupported"}
        base_control.append({
            "node_id": region_index,
            "successors": successors,
            "exit": exit_row,
        })

    analysis_cache: dict[tuple[int, str, str], dict[str, Any]] = {}

    def relation_key(relations: list[dict[str, Any]]) -> str:
        return json.dumps(relations, sort_keys=True, separators=(",", ":"))

    def summary_shape(
        callsite: int,
    ) -> tuple[int, int, list[int]] | None:
        summary = summary_by_callsite.get(callsite)
        if summary is None:
            return None
        try:
            callee = int(summary["callee_region_index"])
            continuation = int(summary["continuation_region_index"])
            returns = sorted({
                int(item) for item in summary["return_region_indices"]
            })
        except (KeyError, TypeError, ValueError):
            return None
        if not (
            0 <= callsite < len(behaviors)
            and 0 <= callee < len(behaviors)
            and 0 <= continuation < len(behaviors)
            and returns
            and all(0 <= item < len(behaviors) for item in returns)
        ):
            return None
        return callee, continuation, returns

    def reachable_nested_calls(
        callee: int,
    ) -> tuple[list[int], dict[str, Any] | None]:
        pending = [callee]
        visited: set[int] = set()
        nested: set[int] = set()
        while pending:
            node = pending.pop()
            if node in visited:
                continue
            if not 0 <= node < len(base_control):
                return [], _callsite_generation_incomplete(
                    node, "reachable_control_node_missing", node_id=node
                )
            visited.add(node)
            if node in translation_issues:
                return [], _callsite_generation_incomplete(
                    node,
                    "control_target_unmapped",
                    node_id=node,
                    reference=translation_issues[node],
                )
            control = base_control[node]
            exit_kind = control["exit"]["kind"]
            if exit_kind == "nested_call":
                nested.add(node)
            for successor in reversed(control["successors"]):
                if successor not in visited:
                    pending.append(successor)
        return sorted(nested), None

    def build_analysis(
        callsite: int,
        requested_relations: list[dict[str, Any]],
        requested_register_relations: list[dict[str, Any]],
        active: tuple[int, ...] = (),
    ) -> dict[str, Any]:
        key = (
            callsite,
            relation_key(requested_relations),
            relation_key(requested_register_relations),
        )
        if callsite in active:
            return _callsite_generation_incomplete(
                callsite,
                "recursive_callsite_summary_dependency",
                node_id=callsite,
                reference=list(active) + [callsite],
            )
        if key in analysis_cache:
            return analysis_cache[key]
        if callsite in duplicate_callsites:
            result = _callsite_generation_incomplete(
                callsite, "call_summary_duplicate", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        summary = summary_by_callsite.get(callsite)
        if summary is None:
            result = _callsite_generation_incomplete(
                callsite, "nested_call_summary_missing", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        if not summary.get("closed"):
            result = _callsite_generation_incomplete(
                callsite, "call_summary_not_closed", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        shape = summary_shape(callsite)
        if shape is None:
            result = _callsite_generation_incomplete(
                callsite, "call_summary_inventory_invalid", node_id=callsite
            )
            analysis_cache[key] = result
            return result
        callee, continuation, returns = shape
        original_call = translated_behaviors[callsite]["original_ir"].get("outcome") or {}
        candidate_call = translated_behaviors[callsite]["candidate_ir"].get("outcome") or {}
        known_indirect = known_indirect_calls.get(callsite)
        direct_shape = all(
            outcome.get(field) == expected
            for outcome in (original_call, candidate_call)
            for field, expected in (
                ("op", "call"), ("target", callee),
                ("continuation", continuation),
            )
        )
        indirect_shape = (
            known_indirect == (callee, continuation)
            and all(
                outcome.get("op") == "indirect_call"
                and outcome.get("continuation") == continuation
                for outcome in (original_call, candidate_call)
            )
        )
        if not direct_shape and not indirect_shape:
            result = _callsite_generation_incomplete(
                callsite, "call_summary_behavior_mismatch", node_id=callsite
            )
            analysis_cache[key] = result
            return result

        dependencies, dependency_issue = reachable_nested_calls(callee)
        if dependency_issue is not None:
            result = dict(dependency_issue)
            result["callsite_id"] = callsite
            analysis_cache[key] = result
            return result
        child_analyses: dict[int, dict[str, Any]] = {}
        for dependency in dependencies:
            child = build_analysis(
                dependency, requested_relations, requested_register_relations,
                active + (callsite,)
            )
            child_analyses[dependency] = child
            if child.get("status") != "satisfied":
                result = _callsite_generation_incomplete(
                    callsite,
                    "nested_callsite_summary_incomplete",
                    node_id=dependency,
                    reference=dependency,
                    nested_reason_codes=list(child.get("reason_codes", [])),
                )
                analysis_cache[key] = result
                return result

        control = json.loads(json.dumps(base_control))
        for dependency, child in child_analyses.items():
            control[dependency]["exit"]["summary_id"] = child[
                "certificate"
            ]["id"]
        result = propose_callsite_preserved_register_summary(
            callsite_id=callsite,
            callee_entry=callee,
            return_inventory=[{
                "return_node_id": return_node,
                "continuation_id": continuation,
            } for return_node in returns],
            requested_relations=requested_relations,
            requested_register_relations=requested_register_relations,
            behaviors=translated_behaviors,
            control=control,
            nested_summaries=[
                child_analyses[dependency]
                for dependency in sorted(child_analyses)
            ],
        )
        analysis_cache[key] = result
        return result

    internal_callsite_node_ids = set(summary_by_callsite)
    for region_index, behavior_pair in enumerate(translated_behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") in {"call", "indirect_call"}
            and candidate_outcome.get("op") == original_outcome.get("op")
        ):
            internal_callsite_node_ids.add(region_index)

    rows: list[dict[str, Any]] = []
    proposal_edges: list[dict[str, Any]] = []
    for callsite in sorted(internal_callsite_node_ids):
        relations = relations_by_callsite.get(callsite, [])
        preserved_register_relations = register_relations_by_callsite.get(
            callsite, [],
        )
        shape = summary_shape(callsite)
        metadata = {
            "callsite_region_index": callsite,
            "callee_region_index": shape[0] if shape is not None else None,
            "continuation_region_index": shape[1] if shape is not None else None,
            "return_region_indices": shape[2] if shape is not None else [],
            "requested_relations": relations,
            "requested_register_relations": preserved_register_relations,
        }
        if not relations and not preserved_register_relations:
            rows.append({
                **metadata,
                "status": "not_applicable",
                "reason_codes": ["no_preservable_relations_at_callsite"],
                "analysis": None,
            })
            continue
        analysis = build_analysis(
            callsite, relations, preserved_register_relations,
        )
        rows.append({
            **metadata,
            "status": analysis["status"],
            "reason_codes": analysis["reason_codes"],
            "analysis": analysis,
        })
        if analysis.get("status") != "satisfied" or shape is None:
            continue
        certificate = analysis["certificate"]
        proposal_edges.append({
            "source_region_index": callsite,
            "target_region_index": shape[1],
            "kind": "internal_callsite_preservation_summary",
            "environment_barrier": False,
            "proposal_only": True,
            "certificate_id": certificate["id"],
            "certificate_hash": certificate["certificate_hash"],
            "preserved_import_relations": certificate["requested_relations"],
            "preserved_register_relations": certificate[
                "requested_register_relations"
            ],
            "return_region_indices": shape[2],
        })

    all_certificates = {
        analysis["certificate"]["id"]: analysis["certificate"]
        for analysis in analysis_cache.values()
        if analysis.get("status") == "satisfied"
    }
    payload = {
        "format": CALLSITE_PRESERVATION_ARTIFACT_FORMAT,
        "status": "proposal_requires_generated_lean_replay",
        "summaries": rows,
        "certificates": [
            all_certificates[certificate_id]
            for certificate_id in sorted(all_certificates)
        ],
        "proposal_edges": proposal_edges,
        "counts": {
            "call_summaries": len(rows),
            "satisfied": sum(row["status"] == "satisfied" for row in rows),
            "incomplete": sum(row["status"] == "incomplete" for row in rows),
            "not_applicable": sum(
                row["status"] == "not_applicable" for row in rows
            ),
            "proposal_edges": len(proposal_edges),
            "certificates": len(all_certificates),
        },
        "trust": {
            "role": "analysis_and_certificate_proposal_only",
            "acceptance_authority": False,
            "required_replay": (
                "Lean must replay every normalized behavior, control edge, "
                "return inventory, nested dependency, and preserved relation"
            ),
        },
    }
    return serialize_callsite_preservation_artifact(
        parse_callsite_preservation_artifact(
            payload,
            region_count=len(behaviors),
        )
    )


def _infer_import_register_invariants(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    seeds: list[dict[str, Any]],
    *,
    internal_return_predecessors: list[dict[str, Any]] | None = None,
    callsite_summary_predecessors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    region_by_numeric_id = {
        int(region["numeric_id"]): index
        for index, region in enumerate(contract.get("regions", []))
    }
    nonvolatile = {"ebx", "esi", "edi", "ebp"}

    def identity_key(imported: dict[str, Any]) -> tuple[str, str, str | int]:
        if "symbol" in imported:
            return (str(imported["dll"]).lower(), "symbol", str(imported["symbol"]))
        return (str(imported["dll"]).lower(), "ordinal", int(imported["ordinal"]))

    identities = {
        identity_key(seed["import"]): seed["import"] for seed in seeds
    }
    seed_facts: dict[int, set[tuple[str, str, tuple[str, str, str | int]]]] = {}
    for seed in seeds:
        seed_facts.setdefault(int(seed["region_index"]), set()).add((
            str(seed["original_register"]),
            str(seed["candidate_register"]),
            identity_key(seed["import"]),
        ))

    edges: list[dict[str, Any]] = []
    incoming: list[list[int]] = [[] for _ in behaviors]
    for source_index, behavior_pair in enumerate(behaviors):
        original_edges = _semantic_edges(behavior_pair["original_ir"])
        candidate_edges = _semantic_edges(behavior_pair["candidate_ir"])
        if len(original_edges) == len(candidate_edges):
            for original_edge, candidate_edge in zip(
                original_edges, candidate_edges, strict=True
            ):
                if (
                    int(original_edge["target"]) != int(candidate_edge["target"])
                    or str(original_edge["kind"]) != str(candidate_edge["kind"])
                ):
                    continue
                target_index = region_by_numeric_id.get(int(original_edge["target"]))
                if target_index is None:
                    continue
                if (
                    _semantic_constant_bool(original_edge["guard"]) is False
                    and _semantic_constant_bool(candidate_edge["guard"]) is False
                ):
                    continue
                edge = {
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "kind": str(original_edge["kind"]),
                    "environment_barrier": bool(
                        original_edge.get("environment_barrier")
                        or candidate_edge.get("environment_barrier")
                    ),
                }
                incoming[target_index].append(len(edges))
                edges.append(edge)
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
            and int(original_outcome.get("continuation", -1))
                == int(candidate_outcome.get("continuation", -2))
        ):
            target_index = region_by_numeric_id.get(
                int(original_outcome["continuation"])
            )
            if target_index is not None:
                incoming[target_index].append(len(edges))
                edges.append({
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "kind": "indirect_external_call_continuation",
                    "environment_barrier": True,
                })

    # Preserve the ordinary decoded predecessor graph separately.  A relation
    # can reach an internal callsite before it is known to be inductive across
    # a surrounding loop: the missing loop edge may itself depend on a
    # callsite-local preservation summary.  These base predecessors support
    # proposal discovery only.  Return and summary edges below remain required
    # to close the authoritative must-hold fixed point.
    base_incoming = [list(edge_indices) for edge_indices in incoming]

    existing_edges = {
        (
            int(edge["source_region_index"]),
            int(edge["target_region_index"]),
            str(edge["kind"]),
        )
        for edge in edges
    }
    callsite_summary_return_pairs: set[tuple[int, int]] = set()
    for predecessor in callsite_summary_predecessors or []:
        if not isinstance(predecessor, dict):
            continue
        target_index = predecessor.get("target_region_index")
        returns = predecessor.get("return_region_indices")
        if not (
            isinstance(target_index, int)
            and not isinstance(target_index, bool)
            and isinstance(returns, list)
            and predecessor.get("proposal_only") is True
            and isinstance(predecessor.get("certificate_id"), str)
            and isinstance(predecessor.get("certificate_hash"), str)
            and isinstance(predecessor.get("preserved_import_relations"), list)
            and predecessor.get("preserved_import_relations")
        ):
            continue
        callsite_summary_return_pairs.update(
            (return_index, target_index)
            for return_index in returns
            if isinstance(return_index, int) and not isinstance(return_index, bool)
        )
    accepted_return_predecessors = 0
    superseded_return_predecessors = 0
    for predecessor in internal_return_predecessors or []:
        source_index = int(predecessor.get("source_region_index", -1))
        target_index = int(predecessor.get("target_region_index", -1))
        key = (source_index, target_index, "internal_return")
        if (
            not 0 <= source_index < len(behaviors)
            or not 0 <= target_index < len(behaviors)
            or key in existing_edges
        ):
            continue
        edge = {
            "source_region_index": source_index,
            "target_region_index": target_index,
            "kind": "internal_return",
            "environment_barrier": False,
        }
        if (source_index, target_index) in callsite_summary_return_pairs:
            edge["superseded_by_callsite_summary"] = True
            superseded_return_predecessors += 1
        else:
            incoming[target_index].append(len(edges))
        edges.append(edge)
        existing_edges.add(key)
        accepted_return_predecessors += 1

    accepted_callsite_summary_predecessors = 0
    for predecessor in callsite_summary_predecessors or []:
        if not isinstance(predecessor, dict):
            continue
        source_value = predecessor.get("source_region_index")
        target_value = predecessor.get("target_region_index")
        if not (
            isinstance(source_value, int)
            and not isinstance(source_value, bool)
            and isinstance(target_value, int)
            and not isinstance(target_value, bool)
        ):
            continue
        source_index = int(source_value)
        target_index = int(target_value)
        key = (
            source_index, target_index,
            "internal_callsite_preservation_summary",
        )
        relations = predecessor.get("preserved_import_relations")
        if (
            not 0 <= source_index < len(behaviors)
            or not 0 <= target_index < len(behaviors)
            or key in existing_edges
            or not isinstance(relations, list)
            or not relations
            or not isinstance(predecessor.get("certificate_id"), str)
            or not isinstance(predecessor.get("certificate_hash"), str)
            or predecessor.get("proposal_only") is not True
        ):
            continue
        allowed_relations: set[
            tuple[str, str, tuple[str, str, str | int]]
        ] = set()
        try:
            for relation in relations:
                imported = identity_key(relation["import"])
                if imported not in identities:
                    raise ValueError
                allowed_relations.add((
                    str(relation["original"]),
                    str(relation["candidate"]),
                    imported,
                ))
        except (KeyError, TypeError, ValueError):
            continue
        incoming[target_index].append(len(edges))
        edges.append({
            "source_region_index": source_index,
            "target_region_index": target_index,
            "kind": "internal_callsite_preservation_summary",
            "environment_barrier": False,
            "proposal_only": True,
            "certificate_id": predecessor["certificate_id"],
            "certificate_hash": predecessor["certificate_hash"],
            "preserved_import_relation_keys": sorted(allowed_relations),
        })
        existing_edges.add(key)
        accepted_callsite_summary_predecessors += 1

    def transferred_source_fact(
        edge: dict[str, Any],
        target_fact: tuple[str, str, tuple[str, str, str | int]],
    ) -> tuple[str, str, tuple[str, str, str | int]] | None:
        source_index = int(edge["source_region_index"])
        original_register, candidate_register, imported = target_fact
        if (
            edge["kind"] == "internal_callsite_preservation_summary"
            and target_fact not in set(edge["preserved_import_relation_keys"])
        ):
            return None
        original_expression = (
            behaviors[source_index]["original_ir"].get("registers") or {}
        ).get(original_register) or {}
        candidate_expression = (
            behaviors[source_index]["candidate_ir"].get("registers") or {}
        ).get(candidate_register) or {}
        if (
            original_expression.get("op") != "input_reg"
            or candidate_expression.get("op") != "input_reg"
        ):
            return None
        if edge["environment_barrier"] and (
            original_register not in nonvolatile
            or candidate_register not in nonvolatile
        ):
            return None
        return (
            str(original_expression["reg"]),
            str(candidate_expression["reg"]),
            imported,
        )

    def edge_supports(
        edge: dict[str, Any],
        target_fact: tuple[str, str, tuple[str, str, str | int]],
        facts: set[tuple[int, str, str, tuple[str, str, str | int]]],
    ) -> bool:
        source_index = int(edge["source_region_index"])
        if target_fact in seed_facts.get(source_index, set()):
            return True
        source_fact = transferred_source_fact(edge, target_fact)
        return source_fact is not None and (source_index, *source_fact) in facts

    def grow_facts(
        predecessor_inventory: list[list[int]],
    ) -> set[tuple[int, str, str, tuple[str, str, str | int]]]:
        result: set[
            tuple[int, str, str, tuple[str, str, str | int]]
        ] = set()
        changed = True
        while changed:
            changed = False
            for target_index, edge_indices in enumerate(predecessor_inventory):
                for edge_index in edge_indices:
                    source_index = int(
                        edges[edge_index]["source_region_index"]
                    )
                    target_facts = set(seed_facts.get(source_index, set()))
                    original_outputs = (
                        behaviors[source_index]["original_ir"].get(
                            "registers"
                        ) or {}
                    )
                    candidate_outputs = (
                        behaviors[source_index]["candidate_ir"].get(
                            "registers"
                        ) or {}
                    )
                    source_facts = [
                        (
                            original_register,
                            candidate_register,
                            imported,
                        )
                        for (
                            region_index,
                            original_register,
                            candidate_register,
                            imported,
                        ) in result
                        if region_index == source_index
                    ]
                    for source_fact in source_facts:
                        imported = source_fact[2]
                        for original_target in original_outputs:
                            for candidate_target in candidate_outputs:
                                target_fact = (
                                    str(original_target),
                                    str(candidate_target),
                                    imported,
                                )
                                if transferred_source_fact(
                                    edges[edge_index], target_fact
                                ) == source_fact:
                                    target_facts.add(target_fact)
                    for target_fact in target_facts:
                        fact = (target_index, *target_fact)
                        if fact not in result and edge_supports(
                            edges[edge_index], target_fact, result
                        ):
                            result.add(fact)
                            changed = True
        return result

    callsite_candidate_facts = grow_facts(base_incoming)
    facts = grow_facts(incoming)

    changed = True
    while changed:
        changed = False
        for fact in list(facts):
            target_index, original_register, candidate_register, imported = fact
            edge_indices = incoming[target_index]
            target_fact = (original_register, candidate_register, imported)
            if not edge_indices or not all(
                edge_supports(edges[edge_index], target_fact, facts)
                for edge_index in edge_indices
            ):
                facts.remove(fact)
                changed = True

    relation_rows = []
    for region_index, original_register, candidate_register, imported in sorted(facts):
        relation_rows.append({
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "import": identities[imported],
            "incoming_edge_indices": incoming[region_index],
            "incoming_edges": [edges[index] for index in incoming[region_index]],
        })

    internal_callsites = {
        region_index
        for region_index, behavior_pair in enumerate(behaviors)
        if (
            (behavior_pair["original_ir"].get("outcome") or {}).get("op")
                == "call"
            and
            (behavior_pair["candidate_ir"].get("outcome") or {}).get("op")
                == "call"
        )
    }
    callsite_candidate_rows = [
        {
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "import": identities[imported],
            "status": "proposal_requires_strict_fixed_point_and_lean_replay",
        }
        for region_index, original_register, candidate_register, imported
        in sorted(callsite_candidate_facts)
        if region_index in internal_callsites
    ]

    call_rows = []
    facts_by_region: dict[int, list[dict[str, Any]]] = {}
    for row in relation_rows:
        facts_by_region.setdefault(int(row["region_index"]), []).append(row)
    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_target = original_outcome.get("target") or {}
        candidate_target = candidate_outcome.get("target") or {}
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
            or original_target.get("op") != "input_reg"
            or candidate_target.get("op") != "input_reg"
        ):
            continue
        matches = [
            row for row in facts_by_region.get(source_index, [])
            if row["original_register"] == original_target.get("reg")
            and row["candidate_register"] == candidate_target.get("reg")
        ]
        if len(matches) != 1:
            continue
        continuation = int(original_outcome.get("continuation", -1))
        if continuation != int(candidate_outcome.get("continuation", -2)):
            continue
        continuation_index = region_by_numeric_id.get(continuation)
        if continuation_index is None:
            continue
        call_rows.append({
            "profile": "inductive_iat_register_call_v1",
            "source_region_index": source_index,
            "continuation_region_index": continuation_index,
            "original_register": str(original_target["reg"]),
            "candidate_register": str(candidate_target["reg"]),
            "import": matches[0]["import"],
        })

    return {
        "format": "stage-a-relational-import-register-invariants-v1",
        "status": "proposal_requires_edge_and_scc_lean_replay",
        "abi_profile": "pe32-win32-nonvolatile-registers-v1",
        "nonvolatile_registers": sorted(nonvolatile),
        "relations": relation_rows,
        "callsite_candidate_relations": callsite_candidate_rows,
        "indirect_import_calls": call_rows,
        "counts": {
            "seeds": len(seeds),
            "relations": len(relation_rows),
            "callsite_candidate_relations": len(callsite_candidate_rows),
            "indirect_import_calls": len(call_rows),
            "internal_return_predecessors": accepted_return_predecessors,
            "superseded_internal_return_predecessors": (
                superseded_return_predecessors
            ),
            "callsite_summary_predecessors": (
                accepted_callsite_summary_predecessors
            ),
        },
    }


def _closed_internal_return_predecessors(
    register_relations: dict[str, Any],
) -> list[dict[str, int]]:
    summaries = (
        register_relations.get("return_slot_analysis", {})
        .get("call_summary_analysis", {})
        .get("summaries", [])
    )
    result: set[tuple[int, int]] = set()
    for summary in summaries:
        if not summary.get("closed"):
            continue
        continuation = int(summary.get("continuation_region_index", -1))
        for return_index in summary.get("return_region_indices", []):
            result.add((int(return_index), continuation))
    return [
        {
            "source_region_index": source_index,
            "target_region_index": target_index,
        }
        for source_index, target_index in sorted(result)
    ]

def _attach_import_register_invariants(
    contract: dict[str, Any], analysis: dict[str, Any],
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    relations_by_region: dict[int, list[dict[str, Any]]] = {}
    for relation in analysis.get("relations", []):
        relations_by_region.setdefault(int(relation["region_index"]), []).append({
            "original": str(relation["original_register"]),
            "candidate": str(relation["candidate_register"]),
            "import": relation["import"],
        })
    for region_index, region in enumerate(refined.get("regions", [])):
        region["input_import_relations"] = sorted(
            relations_by_region.get(region_index, []),
            key=lambda item: (
                item["original"], item["candidate"],
                json.dumps(item["import"], sort_keys=True),
            ),
        )
        region["output_import_relations"] = []
    return refined


def _indirect_fixed_code_pointer_register_calls(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    relation_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Propose register-indirect calls justified by a fixed target invariant.

    This inventory is diagnostic/proof-input data only. Product-graph creation
    must replay the relation and decoded outcomes independently before adding
    any control edge.
    """
    regions = contract.get("regions", [])
    code_targets = contract.get("code_targets", [])
    region_by_numeric_id = {
        int(region["numeric_id"]): region_index
        for region_index, region in enumerate(regions)
        if isinstance(region, dict)
        and isinstance(region.get("numeric_id"), int)
        and not isinstance(region.get("numeric_id"), bool)
    }
    target_ids_by_region_index: dict[int, list[int]] = {}
    for target_id, target in enumerate(code_targets):
        if not (
            isinstance(target, dict)
            and target.get("id") == target_id
            and isinstance(target.get("region_index"), int)
            and not isinstance(target.get("region_index"), bool)
        ):
            continue
        target_ids_by_region_index.setdefault(
            int(target["region_index"]), []
        ).append(target_id)
    result: list[dict[str, Any]] = []
    for source_index, (behavior_pair, relation_row) in enumerate(zip(
        behaviors, relation_rows, strict=True,
    )):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_target = original_outcome.get("target") or {}
        candidate_target = candidate_outcome.get("target") or {}
        original_continuation = original_outcome.get("continuation")
        candidate_continuation = candidate_outcome.get("continuation")
        if not (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
            and isinstance(original_target, dict)
            and isinstance(candidate_target, dict)
            and original_target.get("op") == "input_reg"
            and candidate_target.get("op") == "input_reg"
            and isinstance(original_continuation, int)
            and not isinstance(original_continuation, bool)
            and original_continuation == candidate_continuation
        ):
            continue
        continuation_index = region_by_numeric_id.get(original_continuation)
        if continuation_index is None:
            continue
        continuation_target_ids = target_ids_by_region_index.get(
            continuation_index, []
        )
        if len(continuation_target_ids) != 1:
            continue
        continuation_target_id = continuation_target_ids[0]
        original_register = str(original_target.get("reg"))
        candidate_register = str(candidate_target.get("reg"))
        matches = [
            relation
            for relation in relation_row.get("inputs", [])
            if relation.get("original") == original_register
            and relation.get("candidate") == candidate_register
            and relation.get("relation") == "fixed_code_pointer"
            and isinstance(relation.get("target_id"), int)
            and not isinstance(relation.get("target_id"), bool)
        ]
        if len(matches) != 1:
            continue
        target_id = int(matches[0]["target_id"])
        if not (
            isinstance(code_targets, list)
            and 0 <= target_id < len(code_targets)
            and isinstance(code_targets[target_id], dict)
            and code_targets[target_id].get("id") == target_id
        ):
            continue
        target = code_targets[target_id]
        mapped_region_index = target.get("region_index")
        if "region_index" in target:
            if not (
                isinstance(mapped_region_index, int)
                and not isinstance(mapped_region_index, bool)
                and 0 <= mapped_region_index < len(regions)
            ):
                continue
            target_region_index = int(mapped_region_index)
        else:
            target_region_index = region_by_numeric_id.get(target_id)
        if target_region_index is None:
            continue
        result.append({
            "profile": "inductive_fixed_code_pointer_register_call_v1",
            "source_region_index": source_index,
            "target_region_index": target_region_index,
            "continuation_region_index": continuation_index,
            "continuation_target_id": continuation_target_id,
            "target_id": target_id,
            "original_register": original_register,
            "candidate_register": candidate_register,
        })
    return sorted(
        result,
        key=lambda row: (
            row["source_region_index"], row["target_id"],
            row["continuation_region_index"], row["original_register"],
            row["candidate_register"],
        ),
    )


def _synthesize_register_relations(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
    indirect_call_candidates: list[dict[str, Any]] | None = None,
    import_call_candidates: list[dict[str, Any]] | None = None,
    callsite_summary_predecessors: list[dict[str, Any]] | None = None,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
    _solver_metrics: dict[str, int] | None = None,
    _transfer_cache: dict[
        str, tuple[dict[str, RegisterRelation], dict[str, str]]
    ] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    refined = json.loads(json.dumps(contract))
    regions = refined["regions"]
    region_by_id = {int(region["numeric_id"]): index for index, region in enumerate(regions)}
    launch_root_region_indices = {
        index for index, region in enumerate(regions) if bool(region.get("root"))
    }

    def region_index_for_target_id(target_id: int) -> int | None:
        matching_targets = [
            target for target in refined.get("code_targets", [])
            if int(target["id"]) == target_id
        ]
        if len(matching_targets) != 1:
            return None
        mapped_region_index = matching_targets[0].get("region_index")
        return (
            int(mapped_region_index)
            if isinstance(mapped_region_index, int)
            and not isinstance(mapped_region_index, bool)
            and 0 <= mapped_region_index < len(regions)
            else region_by_id.get(target_id)
        )

    for target_id_value in (refined.get("launch") or {}).get(
        "tls_callback_target_ids", []
    ):
        target_id = int(target_id_value)
        region_index = region_index_for_target_id(target_id)
        if region_index is not None:
            launch_root_region_indices.add(region_index)
    protocol_callback_region_indices = {
        region_index
        for state in (refined.get("protocol_callback_control") or {}).get(
            "states", []
        )
        if isinstance(state, dict)
        and isinstance(state.get("target_id"), int)
        and not isinstance(state.get("target_id"), bool)
        for region_index in [region_index_for_target_id(int(state["target_id"]))]
        if region_index is not None
    }
    predecessors: list[
        list[
            tuple[
                int, bool, str, frozenset[str],
                dict[str, RegisterRelation],
            ]
        ]
    ] = [[] for _ in regions]
    edges: list[dict[str, Any]] = []
    pending_indirect_edges: list[dict[str, Any]] = []
    pending_indirect_jump_edges: list[dict[str, Any]] = []
    pending_import_edges: list[dict[str, Any]] = []
    indirect_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (indirect_call_candidates or [])
    }
    import_call_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (import_call_candidates or [])
    }
    contracts_by_target: dict[
        tuple[str, str, str | int], list[dict[str, Any]]
    ] = {}
    for item in refined.get("machine_import_call_contracts", []):
        imported = item.get("import") or {}
        identity = (
            str(imported.get("dll", "")).lower(),
            "symbol" if "symbol" in imported else "ordinal",
            imported.get("symbol", imported.get("ordinal")),
        )
        contracts_by_target.setdefault(identity, []).append(item)

    def paired_machine_contract(
        original_outcome: dict[str, Any], candidate_outcome: dict[str, Any],
    ) -> dict[str, Any] | None:
        original_identity = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        contracts = (
            contracts_by_target.get(original_identity, [])
            if original_identity is not None
            and original_identity == candidate_identity else []
        )
        if len(contracts) != 1:
            return None
        return contracts[0]

    def machine_preserved_registers(
        contract: dict[str, Any] | None,
    ) -> frozenset[str]:
        if contract is None:
            return frozenset()
        preserved = {
            str(register)
            for register in contract.get("preserved_registers", [])
            if str(register) in _X86_GENERAL_REGISTERS
        }
        if isinstance(contract.get("stack_result_delta"), int):
            preserved.add("esp")
        return frozenset(preserved)

    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_edges = _semantic_edges(behavior_pair["original_ir"])
        candidate_edges = _semantic_edges(behavior_pair["candidate_ir"])
        if len(original_edges) != len(candidate_edges):
            continue
        paired_edges = list(zip(original_edges, candidate_edges, strict=True))
        if any(
            int(original_edge["target"]) != int(candidate_edge["target"])
            or str(original_edge["kind"]) != str(candidate_edge["kind"])
            or bool(original_edge.get("environment_barrier")) !=
                bool(candidate_edge.get("environment_barrier"))
            for original_edge, candidate_edge in paired_edges
        ):
            continue
        for original_edge, candidate_edge in paired_edges:
            target_index = region_by_id.get(int(original_edge["target"]))
            if target_index is None:
                continue
            barrier = bool(original_edge.get("environment_barrier"))
            machine_contract = (
                paired_machine_contract(original_outcome, candidate_outcome)
                if barrier else None
            )
            result_relations = (
                {
                    str(relation["register"]):
                        _machine_result_invariant_relation(relation)
                    for relation in machine_contract.get(
                        "result_register_relations", []
                    )
                }
                if machine_contract is not None else {}
            )
            predecessors[target_index].append(
                (
                    source_index, barrier, str(original_edge["kind"]),
                    (
                        machine_preserved_registers(machine_contract)
                        if barrier else _PE32_EXTERNAL_PRESERVED_REGISTERS
                    ),
                    result_relations,
                )
            )
            edges.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": str(original_edge["kind"]),
                "original_guard": original_edge["guard"],
                "candidate_guard": candidate_edge["guard"],
                "environment_barrier": barrier,
                "requires_call_stack_proof": False,
                "machine_contract_id": (
                    int(machine_contract["id"])
                    if machine_contract is not None else None
                ),
            })
        indirect_candidate = indirect_by_source.get(source_index)
        if indirect_candidate is not None:
            target_index = int(indirect_candidate["target_region_index"])
            indirect_kind = (
                "jump"
                if indirect_candidate["profile"] in {
                    "immutable_relocated_function_pointer_jump_v1",
                    "fixed_static_function_pointer_jump_v1",
                    "fixed_code_address_indirect_jump_v1",
                }
                else "call"
            )
            predecessors[target_index].append(
                (
                    source_index, False, indirect_kind,
                    _PE32_EXTERNAL_PRESERVED_REGISTERS,
                    {},
                )
            )
            pending_edge = {
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": indirect_kind,
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "environment_barrier": False,
                "requires_call_stack_proof": False,
                "indirect_target_profile": indirect_candidate["profile"],
                "indirect_target_claim": indirect_candidate,
            }
            if indirect_kind == "jump":
                pending_indirect_jump_edges.append(pending_edge)
            else:
                pending_indirect_edges.append(pending_edge)
        import_call_candidate = import_call_by_source.get(source_index)
        if import_call_candidate is not None:
            target_index = int(import_call_candidate["continuation_region_index"])
            import_outcome = {"import": import_call_candidate["import"]}
            machine_contract = paired_machine_contract(
                import_outcome, import_outcome
            )
            result_relations = (
                {
                    str(relation["register"]):
                        _machine_result_invariant_relation(relation)
                    for relation in machine_contract.get(
                        "result_register_relations", []
                    )
                }
                if machine_contract is not None else {}
            )
            predecessors[target_index].append(
                (
                    source_index, True, "external_call",
                    machine_preserved_registers(machine_contract),
                    result_relations,
                )
            )
            pending_import_edges.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": "external_call",
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "environment_barrier": True,
                "requires_call_stack_proof": False,
                "indirect_target_profile": import_call_candidate["profile"],
                "import": import_call_candidate["import"],
                "machine_contract_id": (
                    int(machine_contract["id"])
                    if machine_contract is not None else None
                ),
            })
    for edge in edges:
        if edge.get("kind") != "call":
            continue
        caller_index = int(edge["source_region_index"])
        thunk_index = int(edge["target_region_index"])
        caller_outcome = behaviors[caller_index]["original_ir"].get("outcome") or {}
        candidate_caller_outcome = (
            behaviors[caller_index]["candidate_ir"].get("outcome") or {}
        )
        thunk_outcome = behaviors[thunk_index]["original_ir"].get("outcome") or {}
        candidate_thunk_outcome = (
            behaviors[thunk_index]["candidate_ir"].get("outcome") or {}
        )
        if (
            caller_outcome.get("op") != "call"
            or candidate_caller_outcome.get("op") != "call"
            or caller_outcome.get("continuation")
                != candidate_caller_outcome.get("continuation")
            or thunk_outcome.get("op") != "external_jump"
            or candidate_thunk_outcome.get("op") != "external_jump"
        ):
            continue
        original_identity = _semantic_external_target_identity(
            thunk_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_thunk_outcome.get("import")
        )
        contracts = (
            contracts_by_target.get(original_identity, [])
            if original_identity is not None
            and original_identity == candidate_identity else []
        )
        continuation = caller_outcome.get("continuation")
        continuation_index = (
            region_by_id.get(int(continuation))
            if isinstance(continuation, int) else None
        )
        if len(contracts) != 1 or continuation_index is None:
            continue
        contract = contracts[0]
        if contract.get("disposition") != "returns":
            # A terminal or protocol import has no ordinary successor state.
            # Recording it as a returning thunk invents a continuation and can
            # make runtime-frame propagation reject an otherwise valid terminal
            # edge (or worse, relate unreachable code after the call).
            continue
        edge["returning_external_thunk_contract_id"] = int(contract["id"])
        predecessors[continuation_index].append((
            caller_index,
            True,
            "external_jump_return",
            frozenset(
                {str(item) for item in contract["preserved_registers"]}
                | {"esp"}
            ),
            {
                str(relation["register"]):
                    _machine_result_invariant_relation(relation)
                for relation in contract.get(
                    "result_register_relations", []
                )
            },
        ))

    # A return destination is selected by the checked runtime call frame, not by
    # untrusted function recovery. Return continuations therefore participate
    # in rooted reachability but remain absent from decoded predecessor edges;
    # Lean checks the concrete runtime frame at composition time.

    # Keep existing direct edge IDs stable when a new checked indirect-target
    # profile becomes available. Product-graph arrays remain contiguous, while
    # an added indirect edge only changes the tail chunk and its source node's
    # outgoing inventory.
    edges.extend(pending_indirect_edges)
    edges.extend(pending_import_edges)
    edges.extend(pending_indirect_jump_edges)
    for edge in edges:
        edge["direct_call_push_claim"] = _direct_call_push_claim(
            regions[int(edge["source_region_index"])],
            behaviors[int(edge["source_region_index"])],
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        ) if edge["kind"] == "call" else None
        edge["indirect_call_push_claim"] = _indirect_call_push_claim(
            regions[int(edge["source_region_index"])],
            behaviors[int(edge["source_region_index"])],
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        ) if (
            edge["kind"] == "call"
            and edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_call_v1",
                "fixed_static_function_pointer_call_v1",
                "inductive_fixed_code_pointer_register_call_v1",
            }
        ) else None

    return_summary_analysis = _discover_static_call_return_summaries(
        [
            {
                "is_return": (
                    (behavior["original_ir"].get("outcome") or {}).get("op")
                        == "returned"
                    and
                    (behavior["candidate_ir"].get("outcome") or {}).get("op")
                        == "returned"
                ),
            }
            for behavior in behaviors
        ],
        edges,
    )
    callsite_summary_rows = [
        row for row in (callsite_summary_predecessors or [])
        if isinstance(row, dict)
        and row.get("kind") == "internal_callsite_preservation_summary"
    ]
    covered_return_predecessors = {
        (int(return_index), int(row["target_region_index"]))
        for row in callsite_summary_rows
        for return_index in row.get("return_region_indices", [])
        if isinstance(return_index, int) and not isinstance(return_index, bool)
        if isinstance(row.get("preserved_register_relations"), list)
        if any(
            isinstance(relation, dict)
            and str(relation.get("original")) in _X86_GENERAL_REGISTERS
            and relation.get("candidate") == relation.get("original")
            for relation in row.get("preserved_register_relations", [])
        )
    }
    return_predecessors: set[tuple[int, int]] = set()
    for summary in return_summary_analysis["summaries"]:
        if not summary["closed"]:
            continue
        continuation = int(summary["continuation_region_index"])
        for return_index_value in summary["return_region_indices"]:
            return_index = int(return_index_value)
            key = (return_index, continuation)
            if key in covered_return_predecessors:
                continue
            if key in return_predecessors:
                continue
            return_predecessors.add(key)
            predecessors[continuation].append((
                return_index,
                False,
                "internal_return",
                frozenset(),
                {},
            ))
    for summary in callsite_summary_rows:
        try:
            source_index = int(summary["source_region_index"])
            target_index = int(summary["target_region_index"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (
            0 <= source_index < len(regions)
            and 0 <= target_index < len(regions)
        ):
            continue
        preserved_relations: dict[str, RegisterRelation] = {}
        for relation in summary.get("preserved_register_relations", []):
            if not isinstance(relation, dict):
                continue
            original_register = str(relation.get("original"))
            candidate_register = str(relation.get("candidate"))
            if (
                original_register not in _X86_GENERAL_REGISTERS
                or candidate_register != original_register
            ):
                continue
            preserved_relations[original_register] = _register_relation_payload(
                relation
            )
        if not preserved_relations:
            continue
        predecessors[target_index].append((
            source_index,
            False,
            "internal_callsite_preservation_summary",
            frozenset(preserved_relations),
            preserved_relations,
        ))

    successor_regions: list[set[int]] = [set() for _ in regions]
    for target_index, incoming in enumerate(predecessors):
        for source_index, _barrier, _kind, _preserved, _results in incoming:
            successor_regions[source_index].add(target_index)
    components = strongly_connected_components(successor_regions)
    declared_entry_regions = (
        launch_root_region_indices | protocol_callback_region_indices
    )
    conservative_entry_regions = {
        region
        for component_id in components.source_component_ids
        for component in [components.components[component_id]]
        if declared_entry_regions.isdisjoint(component)
        for region in component
    }
    rooted_reachable_regions = set(declared_entry_regions)
    reachability_worklist = list(sorted(declared_entry_regions, reverse=True))
    while reachability_worklist:
        source = reachability_worklist.pop()
        for target in sorted(successor_regions[source]):
            if target in rooted_reachable_regions:
                continue
            rooted_reachable_regions.add(target)
            reachability_worklist.append(target)

    register_order = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    stack_window_input_pairs = [
        {
            (str(window["original_register"]), str(window["candidate_register"]))
            for window in region.get("stack_windows", [])
        }
        for region in regions
    ]
    input_pair_candidates = [
        {
            str(pair["original"]): str(pair["candidate"])
            for pair in region.get("inputs", [])
        }
        for region in regions
    ]
    output_pair_candidates = [
        {
            str(pair["original"]): str(pair["candidate"])
            for pair in region.get("outputs", [])
        }
        for region in regions
    ]
    related_seed = {register: "related_word" for register in register_order}
    input_states: list[dict[str, RegisterRelation] | None] = []
    for region_index in range(len(regions)):
        seeds: list[RegisterRelation] = []
        if region_index in launch_root_region_indices:
            seeds.append("exact")
        if (
            region_index in protocol_callback_region_indices
            or region_index in conservative_entry_regions
        ):
            seeds.append("related_word")
        input_states.append(
            {
                register: _register_relation_join(seeds)
                for register in register_order
            }
            if seeds else None
        )
    output_states: list[dict[str, RegisterRelation] | None] = [
        None for _ in regions
    ]
    output_reason_states: list[dict[str, str] | None] = [
        None for _ in regions
    ]
    max_iterations = max(1, len(regions) * len(register_order) + 1)
    converged = False
    dirty_regions = {
        region_index
        for region_index, state in enumerate(input_states)
        if state is not None
    }
    transfer_evaluations = 0
    transfer_cache_hits = 0
    transfer_cache_misses = 0
    transfer_context_sha256 = sha256_bytes(
        json.dumps(
            {
                "format": "stage-a-register-transfer-context-v1",
                "original_binary_sha256": (
                    getattr(original_bin, "sha256", None)
                ),
                "candidate_binary_sha256": (
                    getattr(candidate_bin, "sha256", None)
                ),
                "original_image_base": original_image_base,
                "candidate_image_base": candidate_image_base,
                "value_targets": refined.get("value_targets", []),
                "code_targets": refined.get("code_targets", []),
                "static_word_relation_slots": refined.get(
                    "static_word_relation_slots", []
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    transfer_region_contexts = [
        sha256_bytes(
            json.dumps(
                {
                    "context_sha256": transfer_context_sha256,
                    "original_registers": behavior_pair["original_ir"][
                        "registers"
                    ],
                    "candidate_registers": behavior_pair["candidate_ir"][
                        "registers"
                    ],
                    "input_pairs": input_pair_candidates[region_index],
                    "output_pairs": output_pair_candidates[region_index],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        for region_index, behavior_pair in enumerate(behaviors)
    ]
    for iteration in range(max_iterations):
        next_outputs = [
            None if row is None else dict(row) for row in output_states
        ]
        next_reasons = [
            None if row is None else dict(row) for row in output_reason_states
        ]
        changed_output_regions: set[int] = set()
        for region_index in sorted(dirty_regions):
            input_kinds = input_states[region_index]
            if input_kinds is None:
                continue
            behavior_pair = behaviors[region_index]
            transfer_evaluations += 1
            original_registers = behavior_pair["original_ir"]["registers"]
            candidate_registers = behavior_pair["candidate_ir"]["registers"]
            transfer_cache_key = transfer_region_contexts[region_index] + ":" + (
                json.dumps(
                    [
                        _register_relation_key(input_kinds[register])
                        for register in register_order
                    ],
                    separators=(",", ":"),
                )
            )
            cached_transfer = (
                _transfer_cache.get(transfer_cache_key)
                if _transfer_cache is not None else None
            )
            if cached_transfer is not None:
                transfer_cache_hits += 1
                cached_kinds, cached_reasons = cached_transfer
                kinds = {
                    register: (
                        dict(relation) if isinstance(relation, dict) else relation
                    )
                    for register, relation in cached_kinds.items()
                }
                reasons = dict(cached_reasons)
            else:
                transfer_cache_misses += 1
                kinds = {}
                reasons = {}
                for register in register_order:
                    candidate_register = output_pair_candidates[region_index].get(
                        register,
                    )
                    if (
                        register not in original_registers
                        or candidate_register is None
                        or candidate_register not in candidate_registers
                    ):
                        kinds[register] = "related_word"
                        reasons[register] = "output_register_pair_missing"
                        continue
                    kinds[register], reasons[register] = (
                        _infer_register_output_relation(
                            original_registers[register],
                            candidate_registers[candidate_register],
                            input_kinds,
                            refined,
                            original_image_base,
                            candidate_image_base,
                            not refined.get("value_targets"),
                            original_bin,
                            candidate_bin,
                            input_pair_candidates[region_index],
                        )
                    )
                if _transfer_cache is not None:
                    _transfer_cache[transfer_cache_key] = (
                        {
                            register: (
                                dict(relation)
                                if isinstance(relation, dict) else relation
                            )
                            for register, relation in kinds.items()
                        },
                        dict(reasons),
                    )
            previous_output = output_states[region_index]
            if previous_output is not None:
                joined_kinds = {
                    register: _register_relation_join([
                        previous_output[register], kinds[register],
                    ])
                    for register in register_order
                }
                for register in register_order:
                    if joined_kinds[register] != kinds[register]:
                        reasons[register] = "monotone_transfer_widening"
                kinds = joined_kinds
            if kinds != previous_output:
                changed_output_regions.add(region_index)
            next_outputs[region_index] = kinds
            next_reasons[region_index] = reasons

        next_inputs = [
            None if row is None else dict(row) for row in input_states
        ]
        affected_inputs = {
            target_index
            for source_index in changed_output_regions
            for target_index in successor_regions[source_index]
        }
        changed_input_regions: set[int] = set()
        for region_index in sorted(affected_inputs):
            region = regions[region_index]
            incoming = predecessors[region_index]
            kinds: dict[str, RegisterRelation] | None = None
            for register in register_order:
                candidates: list[RegisterRelation] = []
                if region_index in launch_root_region_indices:
                    candidates.append("exact")
                if region_index in protocol_callback_region_indices:
                    candidates.append("related_word")
                if region_index in conservative_entry_regions:
                    candidates.append("related_word")
                for source_index, barrier, kind, preserved, results in incoming:
                    source_output = next_outputs[source_index]
                    if source_output is None:
                        continue
                    candidates.append(
                        source_output[register]
                        if kind == "internal_callsite_preservation_summary"
                        and register in preserved
                        and register in results
                        and _register_relation_key(
                            source_output[register]
                        ) == _register_relation_key(results[register])
                        else "related_word"
                        if kind == "internal_callsite_preservation_summary"
                        else
                        source_output[register]
                        if not barrier
                        else results[register]
                        if register in results
                        else source_output[register]
                        if register in preserved
                        else "related_word"
                    )
                if not candidates:
                    continue
                if kinds is None:
                    kinds = {}
                kinds[register] = _register_relation_join(candidates)
                candidate_register = input_pair_candidates[region_index].get(register)
                if (
                    candidate_register is not None
                    and (register, candidate_register)
                        in stack_window_input_pairs[region_index]
                ):
                    # A stack window relates offsets inside paired concrete
                    # ranges; it does not imply literal register equality.
                    kinds[register] = "related_word"
            if kinds is not None and len(kinds) != len(register_order):
                raise AssertionError("reachable register state is incomplete")
            if kinds != input_states[region_index]:
                changed_input_regions.add(region_index)
            next_inputs[region_index] = kinds
        if not changed_input_regions and not changed_output_regions:
            output_reason_states = next_reasons
            converged = True
            break
        input_states = next_inputs
        output_states = next_outputs
        output_reason_states = next_reasons
        dirty_regions = changed_input_regions
    else:
        iteration = max_iterations - 1
    if _solver_metrics is not None:
        _solver_metrics.clear()
        _solver_metrics.update({
            "iterations": iteration + 1,
            "transfer_evaluations": transfer_evaluations,
            "transfer_cache_hits": transfer_cache_hits,
            "transfer_cache_misses": transfer_cache_misses,
        })

    analyzed_regions = {
        region_index
        for region_index, state in enumerate(input_states)
        if state is not None
    }
    input_kinds = [
        dict(state) if state is not None else dict(related_seed)
        for state in input_states
    ]
    output_kinds = [
        dict(state) if state is not None else dict(related_seed)
        for state in output_states
    ]
    output_reasons = [
        dict(reasons) if reasons is not None else {
            register: "unreachable_from_declared_roots"
            for register in register_order
        }
        for reasons in output_reason_states
    ]

    relation_rows: list[dict[str, Any]] = []
    exact_claims = 0
    input_import_pairs = [
        {
            (str(relation["original"]), str(relation["candidate"]))
            for relation in region.get("input_import_relations", [])
        }
        for region in regions
    ]
    output_import_pairs: list[set[tuple[str, str]]] = [set() for _ in regions]
    for edge in edges:
        if not edge["environment_barrier"] and not edge["requires_call_stack_proof"]:
            output_import_pairs[int(edge["source_region_index"])].update(
                input_import_pairs[int(edge["target_region_index"])]
            )
    for region_index, region in enumerate(regions):
        input_pairs = {pair["original"]: pair for pair in region["inputs"]}
        output_pairs = {pair["original"]: pair for pair in region["outputs"]}
        region["input_relations"] = [
            {
                "original": input_pairs[register]["original"],
                "candidate": input_pairs[register]["candidate"],
                **_register_relation_payload(
                    input_kinds[region_index][register]
                ),
            }
            for register in register_order
            if register in input_pairs
            and (
                input_pairs[register]["original"],
                input_pairs[register]["candidate"],
            ) not in input_import_pairs[region_index]
        ]
        region["output_relations"] = [
            {
                "original": output_pairs[register]["original"],
                "candidate": output_pairs[register]["candidate"],
                **_register_relation_payload(
                    output_kinds[region_index][register]
                ),
            }
            for register in register_order
            if register in output_pairs
            and (
                output_pairs[register]["original"],
                output_pairs[register]["candidate"],
            ) not in output_import_pairs[region_index]
        ]
        claims = []
        output_claims = []
        input_relation_by_original = {
            relation["original"]: relation for relation in region["input_relations"]
        }
        for relation in region["output_relations"]:
            register = relation["original"]
            original_expression = behaviors[region_index]["original_ir"]["registers"][register]
            candidate_expression = behaviors[region_index]["candidate_ir"]["registers"][
                relation["candidate"]
            ]
            reason = output_reasons[region_index][register]
            if (
                _register_relation_implies_exact(relation)
                and relation["original"] == relation["candidate"]
                and original_expression == candidate_expression
                and reason not in {
                    "lean_exact_memory_expression", "immutable_image_word",
                    "assembled_immutable_image_word", "static_word_slot",
                    "fixed_immutable_expression",
                }
            ):
                claims.append({
                    "register": register,
                    "relation": "exact",
                    "reason": reason,
                    "expression": original_expression,
                })
            if reason == "identity_transfer":
                input_register = str(original_expression["reg"])
                input_relation = input_relation_by_original.get(input_register)
                if (
                    input_relation is not None
                    and candidate_expression.get("op") == "input_reg"
                    and str(candidate_expression["reg"]) == input_relation["candidate"]
                    and input_relation["relation"] == relation["relation"]
                ):
                    output_claims.append({
                        "kind": "identity",
                        "input": input_relation,
                        "output": relation,
                    })
            elif reason == "paired_constant":
                output_claims.append({
                    "kind": "constant",
                    "output": relation,
                    "original_value": int(original_expression["value"]),
                    "candidate_value": int(candidate_expression["value"]),
                })
            elif reason == "lean_exact_memory_expression":
                output_claims.append({
                    "kind": "exact_memory",
                    "output": relation,
                    "expression": original_expression,
                })
            elif reason in {
                "immutable_image_word", "assembled_immutable_image_word",
            }:
                original_read = (
                    _immutable_image_word_read(original_expression, original_bin)
                    if original_bin is not None else None
                )
                candidate_read = (
                    _immutable_image_word_read(candidate_expression, candidate_bin)
                    if candidate_bin is not None else None
                )
                if (
                    original_read is not None
                    and candidate_read is not None
                ):
                    (
                        original_address, original_writes,
                        original_assembled, original_value,
                    ) = original_read
                    (
                        candidate_address, candidate_writes,
                        candidate_assembled, candidate_value,
                    ) = candidate_read
                    output_claims.append({
                        "kind": "immutable_image_word",
                        "output": relation,
                        "original_address": original_address,
                        "candidate_address": candidate_address,
                        "original_value": original_value,
                        "candidate_value": candidate_value,
                        "original_assembled_read": original_assembled,
                        "candidate_assembled_read": candidate_assembled,
                        "original_writes": original_writes,
                        "candidate_writes": candidate_writes,
                    })
            elif reason == "fixed_immutable_expression":
                if original_bin is not None and candidate_bin is not None:
                    original_fixed, candidate_fixed = _fixed_register_values(
                        input_kinds[region_index],
                        input_pair_candidates[region_index],
                    )
                    original_value = _fixed_immutable_expr_value(
                        original_expression, original_bin, original_fixed,
                    )
                    candidate_value = _fixed_immutable_expr_value(
                        candidate_expression, candidate_bin, candidate_fixed,
                    )
                    if original_value is not None and candidate_value is not None:
                        output_claims.append({
                            "kind": "fixed_immutable_expression",
                            "output": relation,
                            "original_value": original_value,
                            "candidate_value": candidate_value,
                        })
            elif relation["relation"] == "exact" and any(
                claim["register"] == register for claim in claims
            ):
                output_claims.append({
                    "kind": "exact_expression",
                    "output": relation,
                    "expression": original_expression,
                })
        exact_claims += len(claims)
        relation_rows.append({
            "region_id": region["id"],
            "region_index": region_index,
            "analysis_reachable": region_index in analyzed_regions,
            "register_graph_rooted_reachable": (
                region_index in rooted_reachable_regions
            ),
            "inputs": region["input_relations"],
            "outputs": region["output_relations"],
            "runtime_frame_inputs": json.loads(json.dumps(
                region["input_relations"]
            )),
            "runtime_frame_outputs": json.loads(json.dumps(
                region["output_relations"]
            )),
            "exact_output_claims": claims,
            "output_claims": output_claims,
            "return_pop_claim": _return_pop_claim(
                behaviors[region_index], region=region
            ),
            "is_return": (
                (behaviors[region_index]["original_ir"].get("outcome") or {}).get("op")
                    == "returned"
                and (behaviors[region_index]["candidate_ir"].get("outcome") or {}).get("op")
                    == "returned"
            ),
            "fully_exact_output_transfer": (
                len(claims) == len(region["output_relations"])
                and bool(region["output_relations"])
                and all(
                    relation["relation"] == "exact"
                    for relation in region["output_relations"]
                )
            ),
            "fully_supported_output_transfer": (
                len(output_claims) == len(region["output_relations"])
                and bool(region["output_relations"])
            ),
            "predecessor_count": len(predecessors[region_index]),
            "environment_barrier": any(
                barrier for _, barrier, _, _, _ in predecessors[region_index]
            ),
        })

    # Proposal-only inventory. Unlike the legacy indirect candidates accepted
    # as inputs above, these rows do not create predecessors or graph edges.
    indirect_fixed_code_pointer_calls = (
        _indirect_fixed_code_pointer_register_calls(
            refined, behaviors, relation_rows,
        )
    )

    unsupported_edges = 0
    fully_exact_edges = 0
    exact_pair_edge_claims = 0
    edges_with_exact_pair_claims = 0
    for edge in edges:
        source = edge["source_region_index"]
        target = edge["target_region_index"]
        indirect_control = bool(edge.get("indirect_target_profile"))
        immutable_indirect_jump = (
            edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_jump_v1",
                "fixed_code_address_indirect_jump_v1",
            }
        )
        checked_single_target_indirect = (
            immutable_indirect_jump
            or edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_call_v1",
                "fixed_static_function_pointer_call_v1",
                "inductive_fixed_code_pointer_register_call_v1",
            }
        )
        source_claims = {
            claim["register"]: claim
            for claim in relation_rows[source]["exact_output_claims"]
        }
        source_outputs = {
            relation["original"]: relation
            for relation in relation_rows[source]["outputs"]
        }
        pair_claims = [] if (
            edge["environment_barrier"] or edge["requires_call_stack_proof"]
            or indirect_control
        ) else [
            {
                "register": target_relation["original"],
                "target_relation": target_relation["relation"],
                "expression": source_claims[target_relation["original"]]["expression"],
            }
            for target_relation in relation_rows[target]["inputs"]
            if target_relation["relation"] in {"exact", "related_word"}
            and target_relation["original"] in source_claims
            and source_outputs[target_relation["original"]]["candidate"]
                == target_relation["candidate"]
        ]
        edge["exact_output_pair_claims"] = pair_claims
        supported = (
            not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and (not indirect_control or checked_single_target_indirect)
            and all(
            _register_relation_implies(
                output_kinds[source][register], input_kinds[target][register]
            )
            for register in register_order
            )
        )
        edge["relation_preservation_proposed"] = supported
        edge["environment_register_policy"] = (
            {
                "id": _PE32_EXTERNAL_REGISTER_POLICY_ID,
                "preserved": sorted(_PE32_EXTERNAL_PRESERVED_REGISTERS),
                "clobbered": sorted(
                    set(register_order) - _PE32_EXTERNAL_PRESERVED_REGISTERS
                ),
                "status": "requires_relational_environment_compatibility",
            }
            if edge["environment_barrier"]
            else None
        )
        edge["fully_exact_edge_proposed"] = (
            not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and not indirect_control
            and relation_rows[source]["fully_exact_output_transfer"]
            and all(
                relation["relation"] == "exact"
                for relation in relation_rows[target]["inputs"]
            )
            and relation_rows[source]["outputs"] == relation_rows[target]["inputs"]
        )
        unsupported_edges += not supported
        fully_exact_edges += edge["fully_exact_edge_proposed"]
        exact_pair_edge_claims += len(pair_claims)
        edges_with_exact_pair_claims += bool(pair_claims)
    return_slot_analysis = _attach_return_slot_contracts(
        behaviors, relation_rows, edges,
        machine_import_call_contracts=refined.get(
            "machine_import_call_contracts", []
        ),
    )
    counts = {
        "regions": len(regions),
        "dataflow_sccs": len(components.components),
        "dataflow_source_sccs": len(components.source_component_ids),
        "conservative_entry_regions": len(conservative_entry_regions),
        "analyzed_regions": len(analyzed_regions),
        "register_graph_rooted_reachable_regions": len(
            rooted_reachable_regions
        ),
        "register_graph_rooted_reachable_edges": sum(
            int(edge["source_region_index"]) in rooted_reachable_regions
            for edge in edges
        ),
        "direct_edges": len(edges),
        "exact_input_relations": sum(
            _register_relation_kind(kind) == "exact"
            for kinds in input_kinds for kind in kinds.values()
        ),
        "exact_output_relations": sum(
            _register_relation_kind(kind) == "exact"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "code_pointer_output_relations": sum(
            _register_relation_kind(kind) == "code_pointer"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "fixed_code_pointer_output_relations": sum(
            _register_relation_kind(kind) == "fixed_code_pointer"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "fixed_word_input_relations": sum(
            _register_relation_kind(kind) == "fixed_word"
            for kinds in input_kinds for kind in kinds.values()
        ),
        "fixed_word_output_relations": sum(
            _register_relation_kind(kind) == "fixed_word"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "indirect_fixed_code_pointer_calls": len(
            indirect_fixed_code_pointer_calls
        ),
        "data_pointer_output_relations": sum(
            _register_relation_kind(kind) == "data_pointer"
            for kinds in output_kinds for kind in kinds.values()
        ),
        "lean_exact_output_claims": exact_claims,
        "fully_exact_output_regions": sum(
            row["fully_exact_output_transfer"] for row in relation_rows
        ),
        "register_output_claims": sum(
            len(row["output_claims"]) for row in relation_rows
        ),
        "fully_supported_output_regions": sum(
            row["fully_supported_output_transfer"] for row in relation_rows
        ),
        "environment_barrier_edges": sum(edge["environment_barrier"] for edge in edges),
        "environment_register_policy_edges": sum(
            edge["environment_register_policy"] is not None for edge in edges
        ),
        "call_return_edges": sum(
            edge["requires_call_stack_proof"] for edge in edges
        ),
        "direct_call_edges": sum(
            edge["kind"] == "call" and not edge.get("indirect_target_profile")
            for edge in edges
        ),
        "checked_direct_call_pushes": sum(
            edge["direct_call_push_claim"] is not None for edge in edges
        ),
        "checked_indirect_call_pushes": sum(
            edge.get("indirect_call_push_claim") is not None for edge in edges
        ),
        "return_regions": sum(
            (behavior["original_ir"].get("outcome") or {}).get("op") == "returned"
            and (behavior["candidate_ir"].get("outcome") or {}).get("op") == "returned"
            for behavior in behaviors
        ),
        "checked_return_pops": sum(
            row["return_pop_claim"] is not None for row in relation_rows
        ),
        "return_slot_seed_edges": int(return_slot_analysis["seed_edges"]),
        "return_slot_transfer_claims": int(return_slot_analysis["transfer_claims"]),
        "return_slot_transfer_rules": int(return_slot_analysis["transfer_rules"]),
        "return_slot_return_transfer_claims": int(
            return_slot_analysis["return_transfer_claims"]
        ),
        "return_slot_return_transfer_rules": int(
            return_slot_analysis["return_transfer_rules"]
        ),
        "return_slot_call_summary_claims": int(
            return_slot_analysis["call_summary_claims"]
        ),
        "replayable_return_slot_call_summaries": int(
            return_slot_analysis["replayable_call_summaries"]
        ),
        "regions_with_return_slot_offsets": int(
            return_slot_analysis["regions_with_offsets"]
        ),
        "return_regions_with_aligned_runtime_frame": int(
            return_slot_analysis["aligned_returns"]
        ),
        "return_slot_overflow_regions": len(return_slot_analysis["overflow_regions"]),
        "unsupported_edge_proposals": unsupported_edges,
        "fully_exact_edge_proposals": fully_exact_edges,
        "exact_pair_edge_claims": exact_pair_edge_claims,
        "edges_with_exact_pair_claims": edges_with_exact_pair_claims,
    }
    dataflow_complete = converged and len(analyzed_regions) == len(regions)
    artifact = {
        "format": "stage-a-relational-register-relations-v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if dataflow_complete
            else "incomplete"
        ),
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "converged": converged,
        "dataflow_complete": dataflow_complete,
        "iterations": iteration + 1,
        "relation_kinds": sorted(_REGISTER_RELATION_KINDS),
        "trust": {
            "role": "analysis_and_proof_proposal_only",
            "acceptance_rule": (
                "exact output claims and every direct-edge implication must be reconstructed "
                "from decoded behavior and checked by Lean"
            ),
        },
        "return_slot_analysis": return_slot_analysis,
        "indirect_fixed_code_pointer_calls": indirect_fixed_code_pointer_calls,
        "counts": counts,
        "regions": relation_rows,
        "edges": edges,
    }
    return refined, artifact
