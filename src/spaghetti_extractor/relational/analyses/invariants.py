from __future__ import annotations

from typing import Any

import z3

from ..model import _semantic_hash
from ..schema import FLAG_BITS, REGISTERS


_SEMANTIC_FLAG_FIELDS = {
    0: "carry",
    2: "parity",
    6: "zero",
    7: "sign",
    11: "overflow",
}


def _semantic_constant(value: int) -> dict[str, Any]:
    return {"op": "constant", "value": value & 0xFFFFFFFF}

def _semantic_input_register(register: str) -> dict[str, Any]:
    return {"op": "input_reg", "reg": register}

def _semantic_input_flag(index: int) -> dict[str, Any]:
    return {"op": "input_flag", "index": index}

def _semantic_unsigned_less(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {"op": "unsigned_less", "left": left, "right": right}

def _semantic_equal(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {"op": "equal", "left": left, "right": right}

def _semantic_not(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("op") == "bool_constant":
        return {"op": "bool_constant", "value": not value["value"]}
    if value.get("op") == "not":
        return value["value"]
    return {"op": "not", "value": value}

def _semantic_or(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    if left.get("op") == "bool_constant":
        return left if left["value"] else right
    if right.get("op") == "bool_constant":
        return right if right["value"] else left
    return {"op": "or", "left": left, "right": right}

def _semantic_add(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {"op": "add", "left": left, "right": right}

def _semantic_node_count(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + sum(_semantic_node_count(item) for key, item in value.items() if key != "op")
    if isinstance(value, list):
        return sum(_semantic_node_count(item) for item in value)
    return 0

def _substitute_semantic_expr(
    expression: dict[str, Any],
    registers: dict[str, dict[str, Any]],
    flags: dict[str, Any] | None,
) -> dict[str, Any]:
    operation = expression.get("op")
    if operation == "input_reg":
        return registers[expression["reg"]]
    if operation == "input_flag_value":
        condition = _substitute_semantic_flag(int(expression["bit"]), flags)
        return {"op": "bool_to_word", "value": condition}
    result: dict[str, Any] = {"op": operation}
    for key, value in expression.items():
        if key == "op":
            continue
        if isinstance(value, dict) and "op" in value:
            if _semantic_is_boolean(value):
                result[key] = _substitute_semantic_bool(value, registers, flags)
            else:
                result[key] = _substitute_semantic_expr(value, registers, flags)
        elif isinstance(value, list):
            result[key] = [
                _substitute_semantic_expr(item, registers, flags)
                if isinstance(item, dict) and "op" in item
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result

def _semantic_is_boolean(expression: dict[str, Any]) -> bool:
    return expression.get("op") in {
        "bool_constant", "equal", "not", "and", "or", "xor", "unsigned_less",
        "msb", "bit", "input_flag", "division_valid",
    }

def _substitute_semantic_flag(index: int, flags: dict[str, Any] | None) -> dict[str, Any]:
    field = _SEMANTIC_FLAG_FIELDS.get(index)
    if field is None or flags is None or flags.get(field) is None:
        return _semantic_input_flag(index)
    return flags[field]

def _substitute_semantic_bool(
    expression: dict[str, Any],
    registers: dict[str, dict[str, Any]],
    flags: dict[str, Any] | None,
) -> dict[str, Any]:
    operation = expression.get("op")
    if operation == "input_flag":
        return _substitute_semantic_flag(int(expression["index"]), flags)
    if operation == "bool_constant":
        return expression
    result: dict[str, Any] = {"op": operation}
    for key, value in expression.items():
        if key == "op":
            continue
        if isinstance(value, dict) and "op" in value:
            result[key] = (
                _substitute_semantic_bool(value, registers, flags)
                if _semantic_is_boolean(value)
                else _substitute_semantic_expr(value, registers, flags)
            )
        else:
            result[key] = value
    return result

class _SemanticZ3Context:
    def __init__(self) -> None:
        self.registers = {
            register: z3.BitVec(f"reg_{register}", 32) for register in sorted(REGISTERS)
        }
        self.flags = {bit: z3.Bool(f"flag_{bit}") for bit in FLAG_BITS}
        self.memory = z3.Array("memory", z3.BitVecSort(32), z3.BitVecSort(8))
        self.fs_base = z3.BitVec("fs_base", 32)
        self.x87_control = z3.BitVec("x87_control", 32)
        self.x87_status = z3.BitVec("x87_status", 32)
        self.undefined: dict[int, Any] = {}

    def expr(self, expression: dict[str, Any]) -> Any | None:
        operation = expression.get("op")
        if operation == "input_reg":
            return self.registers[expression["reg"]]
        if operation == "input_flag_value":
            return z3.If(self.flags[int(expression["bit"])], z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        if operation == "bool_to_word":
            value = self.boolean(expression["value"])
            return None if value is None else z3.If(value, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        if operation == "input_fs_base":
            return self.fs_base
        if operation == "input_x87_control":
            return self.x87_control
        if operation == "input_x87_status":
            return self.x87_status
        if operation == "constant":
            return z3.BitVecVal(int(expression["value"]) & 0xFFFFFFFF, 32)
        if operation == "undefined":
            slot = int(expression["slot"])
            return self.undefined.setdefault(slot, z3.BitVec(f"undefined_{slot}", 32))
        if operation in {
            "add", "sub", "bit_and", "bit_xor", "bit_or", "multiply",
            "shift_left_by", "shift_right_by", "shift_arithmetic_right_by",
        }:
            left = self.expr(expression["left"])
            right = self.expr(expression["right"])
            if left is None or right is None:
                return None
            return {
                "add": lambda: left + right,
                "sub": lambda: left - right,
                "bit_and": lambda: left & right,
                "bit_xor": lambda: left ^ right,
                "bit_or": lambda: left | right,
                "multiply": lambda: left * right,
                "shift_left_by": lambda: left << (right & z3.BitVecVal(31, 32)),
                "shift_right_by": lambda: z3.LShR(left, right & z3.BitVecVal(31, 32)),
                "shift_arithmetic_right_by": lambda: left >> (right & z3.BitVecVal(31, 32)),
            }[operation]()
        if operation == "bit_not":
            value = self.expr(expression["value"])
            return None if value is None else ~value
        if operation in {"shift_left", "shift_right"}:
            value = self.expr(expression["value"])
            if value is None:
                return None
            amount = int(expression["amount"])
            return value << amount if operation == "shift_left" else z3.LShR(value, amount)
        if operation == "extract_byte":
            value = self.expr(expression["value"])
            if value is None:
                return None
            index = int(expression["index"])
            return z3.ZeroExt(24, z3.Extract(index * 8 + 7, index * 8, value))
        if operation == "bit_value":
            value = self.expr(expression["value"])
            if value is None:
                return None
            index = int(expression["index"])
            return z3.If(
                z3.Extract(index, index, value) == z3.BitVecVal(1, 1),
                z3.BitVecVal(1, 32), z3.BitVecVal(0, 32),
            )
        if operation == "if_equal":
            left = self.expr(expression["left"])
            right = self.expr(expression["right"])
            then_value = self.expr(expression["then"])
            else_value = self.expr(expression["else"])
            if any(value is None for value in (left, right, then_value, else_value)):
                return None
            return z3.If(left == right, then_value, else_value)
        if operation == "unsigned_less_value":
            left = self.expr(expression["left"])
            right = self.expr(expression["right"])
            if left is None or right is None:
                return None
            return z3.If(z3.ULT(left, right), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        if operation == "read8":
            address = self.expr(expression["address"])
            return None if address is None else z3.ZeroExt(24, z3.Select(self.memory, address))
        if operation == "read32":
            address = self.expr(expression["address"])
            if address is None:
                return None
            bytes_ = [z3.Select(self.memory, address + z3.BitVecVal(offset, 32)) for offset in range(4)]
            return z3.Concat(bytes_[3], bytes_[2], bytes_[1], bytes_[0])
        return None

    def boolean(self, expression: dict[str, Any]) -> Any | None:
        operation = expression.get("op")
        if operation == "bool_constant":
            return z3.BoolVal(bool(expression["value"]))
        if operation == "input_flag":
            return self.flags.setdefault(int(expression["index"]), z3.Bool(f"flag_{expression['index']}"))
        if operation == "not":
            value = self.boolean(expression["value"])
            return None if value is None else z3.Not(value)
        if operation in {"and", "or", "xor"}:
            left = self.boolean(expression["left"])
            right = self.boolean(expression["right"])
            if left is None or right is None:
                return None
            return {
                "and": lambda: z3.And(left, right),
                "or": lambda: z3.Or(left, right),
                "xor": lambda: z3.Xor(left, right),
            }[operation]()
        if operation in {"equal", "unsigned_less"}:
            left = self.expr(expression["left"])
            right = self.expr(expression["right"])
            if left is None or right is None:
                return None
            return left == right if operation == "equal" else z3.ULT(left, right)
        if operation in {"msb", "bit"}:
            value = self.expr(expression["value"])
            if value is None:
                return None
            index = 31 if operation == "msb" else int(expression["index"])
            return z3.Extract(index, index, value) == z3.BitVecVal(1, 1)
        return None

def _semantic_tautology(expression: dict[str, Any]) -> tuple[bool, str]:
    context = _SemanticZ3Context()
    translated = context.boolean(expression)
    if translated is None:
        return False, "unsupported_expression"
    solver = z3.Solver()
    solver.add(z3.Not(translated))
    result = solver.check()
    if result == z3.unsat:
        return True, "z3_unsat_candidate_requires_lean_replay"
    if result == z3.sat:
        return False, "counterexample_exists"
    return False, f"solver_unknown:{solver.reason_unknown()}"

def _semantic_edges(behavior: dict[str, Any]) -> list[dict[str, Any]]:
    outcome = behavior["outcome"]
    operation = outcome.get("op")
    truth = {"op": "bool_constant", "value": True}
    if operation in {"jump", "call"}:
        return [{"target": int(outcome["target"]), "guard": truth, "kind": operation}]
    if operation == "branch":
        if int(outcome["taken"]) == int(outcome["fallthrough"]):
            return [{
                "target": int(outcome["taken"]),
                "guard": truth,
                "kind": "branch_converged",
            }]
        return [
            {"target": int(outcome["taken"]), "guard": outcome["condition"], "kind": "branch_taken"},
            {
                "target": int(outcome["fallthrough"]),
                "guard": {"op": "not", "value": outcome["condition"]},
                "kind": "branch_fallthrough",
            },
        ]
    if operation in {"bulk_copy", "atomic_compare_exchange"}:
        return [{"target": int(outcome["continuation"]), "guard": truth, "kind": operation}]
    if operation == "checked_continue":
        return [{"target": int(outcome["continuation"]), "guard": outcome["valid"], "kind": operation}]
    if operation == "external_call":
        return [{
            "target": int(outcome["continuation"]),
            "guard": truth,
            "kind": operation,
            "environment_barrier": True,
        }]
    return []

def _local_invariant_seeds(region: dict[str, Any]) -> list[dict[str, Any]]:
    seeds = []
    for bound_index, bound in enumerate(region.get("bounds", [])):
        for side in ("original", "candidate"):
            seeds.append({
                "id": f"invariant:{region['id']}:{bound_index}:{side}",
                "obligation_id": f"invariant:{region['id']}:{bound_index}",
                "side": side,
                "predicate": _semantic_unsigned_less(
                    bound.get(f"{side}_expression")
                    or _semantic_input_register(bound[side]),
                    _semantic_constant(int(bound["unsigned_lt"])),
                ),
                "kind": "cfg_bound_invariant",
            })
    seen_separations: set[tuple[str, str]] = set()
    for separation_index, separation in enumerate(region.get("address_separations", [])):
        for side in ("original", "candidate"):
            predicate = _semantic_not(_semantic_equal(
                _semantic_add(
                    _semantic_input_register(separation[f"{side}_register"]),
                    _semantic_constant(int(separation[f"{side}_offset"])),
                ),
                _semantic_constant(int(separation[f"{side}_address"])),
            ))
            key = (side, _semantic_hash(predicate))
            if key in seen_separations:
                continue
            seen_separations.add(key)
            seeds.append({
                "id": f"address-separation:{region['id']}:{separation_index}:{side}",
                "obligation_id": f"address-separation:{region['id']}",
                "side": side,
                "predicate": predicate,
                "kind": "cfg_address_separation_invariant",
            })
    return seeds

def _synthesize_relational_invariants(
    contract: dict[str, Any], behaviors: list[dict[str, Any]]
) -> dict[str, Any]:
    index_by_id = {
        int(region["numeric_id"]): index for index, region in enumerate(contract["regions"])
    }
    incoming: dict[str, dict[int, list[dict[str, Any]]]] = {
        "original": {}, "candidate": {},
    }
    for source_index, behavior_pair in enumerate(behaviors):
        for side in ("original", "candidate"):
            for edge in _semantic_edges(behavior_pair[f"{side}_ir"]):
                target_index = index_by_id.get(edge["target"])
                if target_index is None:
                    continue
                incoming[side].setdefault(target_index, []).append({
                    **edge,
                    "source_index": source_index,
                    "target_index": target_index,
                })

    requirements: dict[tuple[str, int], dict[str, dict[str, Any]]] = {}
    queue: list[dict[str, Any]] = []
    seeds: list[dict[str, Any]] = []
    for region_index, region in enumerate(contract["regions"]):
        for seed in _local_invariant_seeds(region):
            record = {**seed, "region_index": region_index, "path": [region_index]}
            predicate_hash = _semantic_hash(seed["predicate"])
            requirements.setdefault((seed["side"], region_index), {})[predicate_hash] = record
            queue.append(record)
            seeds.append(record)

    edge_obligations: list[dict[str, Any]] = []
    barriers: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(queue):
        requirement = queue[cursor]
        cursor += 1
        side = requirement["side"]
        target_index = requirement["region_index"]
        target_region = contract["regions"][target_index]
        predecessors = incoming[side].get(target_index, [])
        if not predecessors:
            barriers.append({
                "kind": (
                    "loader_entry_assumption_required"
                    if target_region.get("root")
                    else "no_static_predecessor"
                ),
                "side": side,
                "region_index": target_index,
                "region_id": target_region["id"],
                "requirement_id": requirement["id"],
            })
        for edge in predecessors:
            source_index = edge["source_index"]
            source_region = contract["regions"][source_index]
            if edge.get("environment_barrier"):
                barriers.append({
                    "kind": "adversarial_environment_transition",
                    "side": side,
                    "source_index": source_index,
                    "source_id": source_region["id"],
                    "target_index": target_index,
                    "target_id": target_region["id"],
                    "requirement_id": requirement["id"],
                })
                continue
            source_behavior = behaviors[source_index][f"{side}_ir"]
            postcondition = _substitute_semantic_bool(
                requirement["predicate"],
                source_behavior["registers"],
                source_behavior.get("flags"),
            )
            precondition = _semantic_or(_semantic_not(edge["guard"]), postcondition)
            tautology, solver_status = _semantic_tautology(precondition)
            edge_id = (
                f"edge:{side}:{source_region['numeric_id']}:{target_region['numeric_id']}:"
                f"{_semantic_hash(requirement['predicate'])[:16]}"
            )
            edge_obligations.append({
                "id": edge_id,
                "side": side,
                "source_index": source_index,
                "source_id": source_region["id"],
                "target_index": target_index,
                "target_id": target_region["id"],
                "edge_kind": edge["kind"],
                "requirement_id": requirement["id"],
                "precondition": precondition,
                "precondition_sha256": _semantic_hash(precondition),
                "nodes": _semantic_node_count(precondition),
                "analysis_status": "candidate_tautology" if tautology else "requires_predecessor_invariant",
                "solver_status": solver_status,
                "lean_status": "pending",
            })
            if tautology:
                continue
            derived_hash = _semantic_hash(precondition)
            bucket = requirements.setdefault((side, source_index), {})
            if derived_hash in bucket:
                continue
            if source_index in requirement["path"]:
                barriers.append({
                    "kind": "loop_invariant_fixpoint_required",
                    "side": side,
                    "source_index": source_index,
                    "source_id": source_region["id"],
                    "target_index": target_index,
                    "target_id": target_region["id"],
                    "requirement_id": requirement["id"],
                    "precondition": precondition,
                })
                continue
            derived = {
                "id": f"derived:{side}:{source_region['numeric_id']}:{derived_hash[:16]}",
                "obligation_id": requirement["obligation_id"],
                "side": side,
                "predicate": precondition,
                "kind": requirement["kind"],
                "region_index": source_index,
                "path": requirement["path"] + [source_index],
                "derived_from": requirement["id"],
            }
            bucket[derived_hash] = derived
            queue.append(derived)

    obligations: dict[str, dict[str, Any]] = {}
    for seed in seeds:
        item = obligations.setdefault(seed["obligation_id"], {
            "id": seed["obligation_id"],
            "kind": seed["kind"],
            "seed_count": 0,
            "candidate_tautology_edges": 0,
            "open_predecessor_edges": 0,
            "barriers": [],
            "status": "candidate_requires_lean_replay",
        })
        item["seed_count"] += 1
    requirement_by_id = {
        requirement["id"]: requirement
        for bucket in requirements.values()
        for requirement in bucket.values()
    }
    for edge in edge_obligations:
        requirement = requirement_by_id[edge["requirement_id"]]
        item = obligations[requirement["obligation_id"]]
        if edge["analysis_status"] == "candidate_tautology":
            item["candidate_tautology_edges"] += 1
        else:
            item["open_predecessor_edges"] += 1
    for barrier in barriers:
        requirement = requirement_by_id.get(barrier["requirement_id"])
        if requirement is not None:
            obligations[requirement["obligation_id"]]["barriers"].append(barrier["kind"])
    for item in obligations.values():
        item["barriers"] = sorted(set(item["barriers"]))
        if item["barriers"]:
            item["status"] = "incomplete"

    region_invariants = []
    for (side, region_index), bucket in sorted(requirements.items()):
        region_invariants.append({
            "side": side,
            "region_index": region_index,
            "region_id": contract["regions"][region_index]["id"],
            "predicates": [
                {
                    "id": requirement["id"],
                    "obligation_id": requirement["obligation_id"],
                    "predicate": requirement["predicate"],
                    "predicate_sha256": _semantic_hash(requirement["predicate"]),
                    "nodes": _semantic_node_count(requirement["predicate"]),
                }
                for requirement in sorted(bucket.values(), key=lambda item: item["id"])
            ],
        })
    return {
        "format": "stage-a-relational-invariants-v1",
        "status": "analysis_candidates_only",
        "trust": {
            "z3": "untrusted_candidate_generator",
            "acceptance": "all candidate tautologies and edge preservation claims require Lean replay",
        },
        "counts": {
            "seeds": len(seeds),
            "region_invariants": sum(len(item["predicates"]) for item in region_invariants),
            "edge_obligations": len(edge_obligations),
            "candidate_tautology_edges": sum(
                edge["analysis_status"] == "candidate_tautology" for edge in edge_obligations
            ),
            "barriers": len(barriers),
        },
        "obligations": sorted(obligations.values(), key=lambda item: item["id"]),
        "region_invariants": region_invariants,
        "edge_obligations": edge_obligations,
        "barriers": barriers,
    }

def _attach_invariant_synthesis(
    proof_ir: dict[str, Any], synthesis: dict[str, Any]
) -> dict[str, Any]:
    by_id = {item["id"]: item for item in synthesis["obligations"]}
    updated = dict(proof_ir)
    updated["obligations"] = [
        {
            **obligation,
            "analysis": by_id[obligation["id"]],
            "blocker": (
                "generic weakest-precondition candidates were found but their edge "
                "preservation theorems have not yet been replayed by Lean"
                if by_id[obligation["id"]]["status"] != "incomplete"
                else "generic invariant synthesis reached an explicit control/environment boundary"
            ),
            "next_action": (
                "emit and check the candidate edge-preservation theorems in Lean"
                if by_id[obligation["id"]]["status"] != "incomplete"
                else "supply a checked loop, loader-entry, call-summary, or environment invariant"
            ),
        }
        if obligation["id"] in by_id else obligation
        for obligation in proof_ir["obligations"]
    ]
    return updated
