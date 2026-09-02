"""Veto-only host evaluator for executable-transfer-plan-v2.

It intentionally has no PE, ingress, candidate-output, or authority API.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .model import TransferPlanError, _Call, _Node, _Transfer
from .plan import load_executable_transfer_plan
from .interpretation import (
    DomainOperationCoverageV2,
    total_domain_coverage_v2,
)

_REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_CONCRETE_REJECTED_EXPRESSIONS_V2 = frozenset({
    "fpu_control",
    "fpu_status",
    "fpu_tag",
    "fpu_pending_exception",
    "fpu_last_opcode",
    "fpu_instruction_pointer",
    "fpu_code_selector",
    "fpu_data_pointer",
    "fpu_data_selector",
})


def concrete_operation_coverage_v2() -> DomainOperationCoverageV2:
    return total_domain_coverage_v2(
        "concrete_evaluator",
        rejected_expressions=_CONCRETE_REJECTED_EXPRESSIONS_V2,
        rejected_effects={"typed_x87"},
    )


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _s32(value: int) -> int:
    value = _u32(value)
    return value - 0x100000000 if value & 0x80000000 else value


class _MemoryFault(Exception):
    pass


class _SemanticFault(Exception):
    pass


@dataclass
class EvaluatorStateV1:
    registers: dict[str, int] = field(default_factory=lambda: {name: 0 for name in _REGS})
    flags: dict[str, int] = field(default_factory=lambda: {name: 0 for name in _FLAGS})
    eflags: int = 0
    fs_base: int = 0
    original_rva: int = 0

    @classmethod
    def from_payload(cls, raw: Mapping[str, Any] | None) -> "EvaluatorStateV1":
        payload = dict(raw or {})
        registers, flags = payload.get("registers", {}), payload.get("flags", {})
        if not isinstance(registers, Mapping) or set(registers) - set(_REGS):
            raise TransferPlanError("evaluator register state is malformed")
        if not isinstance(flags, Mapping) or set(flags) - set(_FLAGS):
            raise TransferPlanError("evaluator flag state is malformed")
        return cls(
            registers={name: _u32(int(registers.get(name, 0))) for name in _REGS},
            flags={name: int(flags.get(name, 0)) & 1 for name in _FLAGS},
            eflags=_u32(int(payload.get("eflags", 0))),
            fs_base=_u32(int(payload.get("fs_base", 0))),
            original_rva=_u32(int(payload.get("original_rva", 0))),
        )

    def copy(self) -> "EvaluatorStateV1":
        return EvaluatorStateV1(dict(self.registers), dict(self.flags), self.eflags, self.fs_base, self.original_rva)

    def payload(self) -> dict[str, Any]:
        return {
            "registers": dict(self.registers), "flags": dict(self.flags),
            "eflags": self.eflags, "fs_base": self.fs_base,
            "original_rva": self.original_rva,
        }


class EvaluatorMemoryV1:
    def __init__(self, values: Mapping[int, int] | None = None) -> None:
        self.bytes = {_u32(int(key)): int(value) & 0xFF for key, value in (values or {}).items()}

    @classmethod
    def from_payload(cls, raw: object) -> "EvaluatorMemoryV1":
        if raw is None:
            return cls()
        if not isinstance(raw, list):
            raise TransferPlanError("evaluator memory is not a segment list")
        values: dict[int, int] = {}
        for index, item in enumerate(raw):
            if not isinstance(item, Mapping) or isinstance(item.get("address"), bool) or not isinstance(item.get("address"), int):
                raise TransferPlanError(f"evaluator memory segment {index} is malformed")
            data = item.get("bytes_hex")
            if not isinstance(data, str) or len(data) % 2:
                raise TransferPlanError(f"evaluator memory segment {index} is malformed")
            try:
                decoded = bytes.fromhex(data)
            except ValueError as exc:
                raise TransferPlanError(f"evaluator memory segment {index} is malformed") from exc
            for offset, value in enumerate(decoded):
                address = _u32(int(item["address"]) + offset)
                if address in values:
                    raise TransferPlanError("evaluator memory segments overlap")
                values[address] = value
        return cls(values)

    def read(self, address: int, width: int) -> int:
        if width not in {1, 2, 4}:
            raise _SemanticFault
        try:
            return _u32(sum(self.bytes[_u32(address + offset)] << (8 * offset) for offset in range(width)))
        except KeyError as exc:
            raise _MemoryFault from exc

    def write(self, address: int, width: int, value: int) -> None:
        if width not in {1, 2, 4}:
            raise _SemanticFault
        addresses = [_u32(address + offset) for offset in range(width)]
        if any(item not in self.bytes for item in addresses):
            raise _MemoryFault
        for offset, item in enumerate(addresses):
            self.bytes[item] = (value >> (8 * offset)) & 0xFF

    def payload(self) -> list[dict[str, int]]:
        return [{"address": key, "value": self.bytes[key]} for key in sorted(self.bytes)]


CallHandler = Callable[[_Call, EvaluatorStateV1, tuple[int, ...]], tuple[str, EvaluatorStateV1]]


def evaluate_transfer_plan_case(
    transfer_plan: Path,
    case: Mapping[str, Any],
    *,
    call_handler: CallHandler | None = None,
) -> dict[str, Any]:
    plan, transfers = load_executable_transfer_plan(Path(transfer_plan), require_complete=True)
    if case.get("format") != "spaghetti-extractor-transfer-evaluator-case-v1":
        raise TransferPlanError("transfer evaluator case has an unsupported format")
    entry, limit = case.get("entry_rva"), case.get("max_steps", 1024)
    if isinstance(entry, bool) or not isinstance(entry, int) or isinstance(limit, bool) or not isinstance(limit, int) or not 0 < limit <= 1_000_000:
        raise TransferPlanError("transfer evaluator case bounds are malformed")
    raw_state = case.get("state")
    if raw_state is not None and not isinstance(raw_state, Mapping):
        raise TransferPlanError("evaluator state is malformed")
    state = EvaluatorStateV1.from_payload(raw_state)
    memory = EvaluatorMemoryV1.from_payload(case.get("memory"))
    raw_undefined = case.get("undefined_values", {})
    if not isinstance(raw_undefined, Mapping):
        raise TransferPlanError("evaluator undefined-value map is malformed")
    undefined = {int(key): _u32(int(value)) for key, value in raw_undefined.items()}
    by_rva = {item.rva_start: item for item in transfers}
    current, trace = _u32(entry), []
    result = _result("unimplemented", current)
    for _ in range(limit):
        transfer = by_rva.get(current)
        if transfer is None:
            break
        result = _evaluate_transfer(transfer, state, memory, undefined, call_handler)
        trace.append({"unit_id": transfer.identity, "rva": current, "result": dict(result)})
        if result["kind"] not in {"fallthrough", "jump", "branch"}:
            break
        current = result["target_rva"]
    observation = {
        "format": "spaghetti-extractor-transfer-evaluator-observation-v1",
        "authority": "none; veto-only diagnostic observation",
        "transfer_plan_sha256": plan["plan_sha256"],
        "case_id": str(case.get("id") or "anonymous"),
        "result": result, "state": state.payload(), "memory": memory.payload(),
        "trace": trace,
    }
    observation["observation_sha256"] = canonical_sha256_v3(observation)
    return observation


def generated_differential_cases(transfer_plan: Path) -> list[dict[str, Any]]:
    plan, _ = load_executable_transfer_plan(Path(transfer_plan), require_complete=True)
    return [
        {
            "format": "spaghetti-extractor-transfer-evaluator-case-v1",
            "id": f"rva-{rva:08x}-pattern-{index}", "entry_rva": rva,
            "max_steps": 64,
            "state": {
                "registers": {name: _u32(pattern + slot) for slot, name in enumerate(_REGS)},
                "flags": {name: (pattern >> slot) & 1 for slot, name in enumerate(_FLAGS)},
                "eflags": 2,
            },
            "memory": [], "undefined_values": {},
        }
        for rva in plan["entry_targets"]
        for index, pattern in enumerate((0, 0x55555555, 0xAAAAAAAA, 0xFFFFFFFF))
    ]


def compare_observations(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> dict[str, Any]:
    mismatches = [name for name in ("result", "state", "memory", "trace") if expected.get(name) != observed.get(name)]
    return {
        "format": "spaghetti-extractor-transfer-differential-result-v1",
        "authority": "none; mismatch veto only",
        "status": "match" if not mismatches else "mismatch",
        "mismatched_fields": mismatches,
    }


def inspect_transfer_plan(transfer_plan: Path) -> dict[str, Any]:
    """Return a compact workbench view without copying executable semantics."""

    plan, transfers = load_executable_transfer_plan(Path(transfer_plan))
    return {
        "format": "spaghetti-extractor-transfer-workbench-view-v1",
        "authority": "none; inspection only",
        "status": plan["status"],
        "plan_sha256": plan["plan_sha256"],
        "bindings": dict(plan["bindings"]),
        "units": [
            {
                "id": row.identity, "rva_start": row.rva_start,
                "word_expressions": len(row.nodes), "actions": len(row.actions),
                "calls": len(row.calls), "x87_operations": len(row.x87_operations),
            }
            for row in transfers
        ],
        "runtime_provider_requirements": list(plan["runtime_provider_requirements"]),
        "semantic_blockers": list(plan["semantic_blockers"]),
    }


ObservationRunner = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def minimize_mismatch_case(
    case: Mapping[str, Any],
    expected_runner: ObservationRunner,
    observed_runner: ObservationRunner,
) -> dict[str, Any]:
    """Greedily shrink diagnostic input while preserving an exact mismatch."""

    candidate = copy.deepcopy(dict(case))

    def differs(value: Mapping[str, Any]) -> bool:
        return compare_observations(
            expected_runner(value), observed_runner(value)
        )["status"] == "mismatch"

    if not differs(candidate):
        raise TransferPlanError("cannot minimize a matching differential case")
    memory = candidate.get("memory")
    if isinstance(memory, list):
        for index in range(len(memory) - 1, -1, -1):
            proposal = copy.deepcopy(candidate)
            del proposal["memory"][index]
            if differs(proposal):
                candidate = proposal
    state = candidate.get("state")
    if isinstance(state, dict):
        for inventory in ("registers", "flags"):
            fields = state.get(inventory)
            if isinstance(fields, dict):
                for name in sorted(tuple(fields)):
                    proposal = copy.deepcopy(candidate)
                    proposal["state"][inventory][name] = 0
                    if differs(proposal):
                        candidate = proposal
    return candidate


def _evaluate_transfer(
    transfer: _Transfer, state: EvaluatorStateV1, memory: EvaluatorMemoryV1,
    undefined: Mapping[int, int], call_handler: CallHandler | None,
) -> dict[str, Any]:
    initial, call_output, words = state.copy(), state.copy(), {}
    state.original_rva = transfer.rva_start

    def word(index: int) -> int:
        if index not in words:
            if index < 0 or index >= len(transfer.nodes):
                raise _SemanticFault
            words[index] = _u32(_eval_node(transfer.nodes[index], word, initial, state, call_output, memory, undefined))
        return words[index]

    def cached(index: int) -> int:
        if index not in words:
            raise _SemanticFault
        return words[index]

    try:
        for action in transfer.actions:
            op = action.op
            if op == "eval_word": word(action.args[0])
            elif op.startswith("set_x87") or op in {"eval_x87", "typed_x87"}: return _result("unimplemented", transfer.rva_start)
            elif op == "memory_write": memory.write(cached(action.args[0]), action.aux, cached(action.args[1]))
            elif op == "divide_if" and cached(action.args[0]): return _result("divide_error")
            elif op == "access_violation_if" and cached(action.args[0]):
                cached(action.args[1]); cached(action.args[2])
                return _result("memory_fault", transfer.rva_start)
            elif op == "call":
                call = transfer.calls[action.args[0]]
                call_state = state.copy()
                for slot, name in enumerate(_REGS): call_state.registers[name] = cached(call.register_nodes[slot])
                for slot, name in enumerate(_FLAGS): call_state.flags[name] = cached(call.flag_nodes[slot]) & 1
                if call_handler is None: return _result("unimplemented", transfer.rva_start)
                status, call_output = call_handler(call, call_state, tuple(cached(item) for item in call.argument_nodes))
                state.registers, state.flags = dict(call_output.registers), dict(call_output.flags)
                state.eflags, state.fs_base, state.original_rva = call_output.eflags, call_output.fs_base, call_output.original_rva
                if status != "ok": return _result(status if status in {"divide_error", "memory_fault", "external_fault"} else "unimplemented", call_output.original_rva)
            elif op in {"rep_movsd", "rep_movs"}: _repeat_move(state, memory, *(cached(item) for item in action.args), 4 if op == "rep_movsd" else action.aux)
            elif op in {"rep_stosd", "rep_stos"}: _repeat_store(state, memory, *(cached(item) for item in action.args), 4 if op == "rep_stosd" else action.aux)
            elif op == "rep_scas": _repeat_scan(state, memory, *(cached(item) for item in action.args))
            elif op == "set_reg": state.registers[_REGS[action.aux]] = cached(action.args[0])
            elif op == "set_flag": _set_flag(state, action.aux, cached(action.args[0]))
            elif op == "sync_eflags": _sync_eflags(state)
            elif op == "outcome_fallthrough": return _result("fallthrough", action.args[0])
            elif op == "outcome_jump": return _result("jump", action.args[0])
            elif op == "outcome_branch": return _result("branch", action.args[1] if cached(action.args[0]) else action.args[2])
            elif op == "outcome_return": return _result("return", value=cached(action.args[0]))
            elif op == "outcome_indirect": return _result("indirect_jump", value=cached(action.args[0]))
            elif op == "outcome_nonlocal": return _result(
                "nonlocal", cached(action.args[0]), cached(action.args[1])
            )
            elif op == "outcome_external": return _result("external_jump")
            elif op == "atomic_compare_exchange":
                address, expected, desired = (cached(item) for item in action.args[:3])
                observed = memory.read(address, action.aux)
                if observed == (expected & ((1 << (8 * action.aux)) - 1)): memory.write(address, action.aux, desired)
                words[action.args[3]] = observed
            elif op == "atomic_exchange":
                address, desired = (cached(item) for item in action.args[:2])
                observed = memory.read(address, action.aux); memory.write(address, action.aux, desired); words[action.args[2]] = observed
            elif op not in {"divide_if", "access_violation_if"}: raise _SemanticFault
    except _MemoryFault:
        return _result("memory_fault", transfer.rva_start)
    except _SemanticFault:
        return _result("unimplemented", transfer.rva_start)
    return _result("unimplemented", transfer.rva_start)


def _eval_node(node: _Node, word: Callable[[int], int], initial: EvaluatorStateV1, current: EvaluatorStateV1, call: EvaluatorStateV1, memory: EvaluatorMemoryV1, undefined: Mapping[int, int]) -> int:
    values, op = [word(item) for item in node.args], node.op
    if op == "const": return node.immediate
    if op == "reg": return (current if node.immediate else initial).registers[_REGS[node.aux]]
    if op == "flag": return _get_flag(current if node.immediate else initial, node.aux)
    if op == "fs_base": return (current if node.immediate else initial).fs_base
    if op in {"true", "false"}: return int(op == "true")
    if op in {"undefined_bv", "undefined_flag"}: return undefined.get(node.immediate, values[0] if values else 0)
    if op == "call_response": return call.registers[_REGS[node.aux]]
    if op == "call_flag": return _get_flag(call, node.aux)
    if op == "load": return memory.read(values[0], node.aux)
    if op == "sub32": return values[0] - values[1]
    if op == "ult32": return int(values[0] < values[1])
    if op in {"eq", "eq_bool"}: return int(values[0] == values[1])
    if op == "xor_bool": return int(bool(values[0]) != bool(values[1]))
    if op == "add32": return sum(values)
    if op == "mul32": return _fold(values, 1, lambda a, b: a * b)
    if op == "xor32": return _fold(values, 0, lambda a, b: a ^ b)
    if op == "and32": return _fold(values, 0xFFFFFFFF, lambda a, b: a & b)
    if op == "or32": return _fold(values, 0, lambda a, b: a | b)
    if op == "not32": return ~values[0]
    if op == "neg32": return -values[0]
    if op == "shl32": return values[0] << (values[1] & 31)
    if op == "lshr32": return values[0] >> (values[1] & 31)
    if op == "sar": return _sar(values[1], values[2], values[0])
    if op == "sign_extend": return _sign_extend(values[1], values[0])
    if op == "ite": return values[1] if values[0] else values[2]
    if op == "msb": return (values[-1] >> ((values[0] if len(values) == 2 else 32) - 1)) & 1
    if op == "not": return int(not values[0])
    if op == "and_bool": return int(all(values))
    if op == "or_bool": return int(any(values))
    if op == "parity": return int((values[1] & 0xFF).bit_count() % 2 == 0)
    if op == "bool_to_bit": return int(bool(values[0]))
    if op == "add_overflow": return _overflow(values, subtract=False)
    if op == "sub_overflow": return _overflow(values, subtract=True)
    if op in {"imul_low32", "mul_low32"}: return values[0] * values[1]
    if op == "imul_high32": return (_s32(values[0]) * _s32(values[1]) >> 32) & 0xFFFFFFFF
    if op == "mul_high32": return (values[0] * values[1] >> 32) & 0xFFFFFFFF
    if op == "imul_overflow": return int(values[4] != (0xFFFFFFFF if _s32(values[3]) < 0 else 0))
    if op == "mul_carry": return int(values[3] != 0)
    if op.startswith("udiv_"): return _udiv(values)[{"udiv_quot32": 0, "udiv_rem32": 1, "udiv_valid32": 2}[op]]
    if op == "bsr_index": return 0 if not values[-1] else values[-1].bit_length() - 1
    if op == "tzcnt": return 32 if not values[-1] else (values[-1] & -values[-1]).bit_length() - 1
    if op == "sbb_borrow": return _sbb(values, overflow=False)
    if op == "sbb_overflow": return _sbb(values, overflow=True)
    if op in {"adc_carry", "adc_overflow"}: return _adc(values, overflow=op.endswith("overflow"))
    if op in {"shift_cf", "shift_of"}: return _shift(op, node.aux, values)
    if op == "fpu_control_init": return 0x037F
    if op == "fpu_status_init": return 0
    if op in _CONCRETE_REJECTED_EXPRESSIONS_V2: raise _SemanticFault
    if op in {"fpu_control_load", "fpu_control_word", "fpu_status_word"}: return values[0] & 0xFFFF
    raise _SemanticFault


def _result(kind: str, target_rva: int = 0, value: int = 0) -> dict[str, Any]:
    return {"kind": kind, "target_rva": _u32(target_rva), "value": _u32(value)}


def _fold(values: list[int], start: int, fn: Callable[[int, int], int]) -> int:
    result = start
    for value in values: result = _u32(fn(result, value))
    return result


def _sign_extend(value: int, width: int) -> int:
    if not 0 < width <= 32: raise _SemanticFault
    mask = 0xFFFFFFFF if width == 32 else (1 << width) - 1
    value &= mask
    return _u32(value | (~mask if value & (1 << (width - 1)) else 0))


def _sar(value: int, count: int, width: int) -> int:
    return _u32((_s32(value) if width == 32 else _s32(_sign_extend(value, width))) >> (count & 31))


def _overflow(values: list[int], *, subtract: bool) -> int:
    width, left, right, result = values
    if not 0 < width <= 32: raise _SemanticFault
    sign = 1 << (width - 1)
    return int((((left ^ right) if subtract else ~(left ^ right)) & (left ^ result) & sign) != 0)


def _udiv(values: list[int]) -> tuple[int, int, int]:
    high, low, divisor = values
    if not divisor or high >= divisor: return 0, 0, 0
    dividend = (high << 32) | low
    return _u32(dividend // divisor), _u32(dividend % divisor), 1


def _sbb(values: list[int], *, overflow: bool) -> int:
    width, left, right, borrow, result = values
    if not 0 < width <= 32 or borrow > 1: raise _SemanticFault
    mask = 0xFFFFFFFF if width == 32 else (1 << width) - 1
    if ((left - right - borrow) & mask) != (result & mask): raise _SemanticFault
    return _overflow([width, left, _u32(right + borrow), result], subtract=True) if overflow else int((left & mask) < ((right & mask) + borrow))


def _adc(values: list[int], *, overflow: bool) -> int:
    width, left, right, carry, result = values
    if not 0 < width <= 32 or carry > 1: raise _SemanticFault
    mask = 0xFFFFFFFF if width == 32 else (1 << width) - 1
    total = (left & mask) + (right & mask) + carry
    if (total & mask) != (result & mask): raise _SemanticFault
    return _overflow([width, left, right, result], subtract=False) if overflow else (total >> width) & 1


def _shift(op: str, aux: int, values: list[int]) -> int:
    kind, width, count = aux >> 8, aux & 0xFF, values[1] & 31
    if not 0 < width <= 32: raise _SemanticFault
    if count == 0: return values[2] & 1
    if op == "shift_cf":
        if kind == 0: return (values[0] >> (width - count)) & 1 if count <= width else 0
        return (values[0] >> (count - 1)) & 1 if count <= width else ((values[0] >> (width - 1)) & 1 if kind == 2 else 0)
    if count != 1: return 0
    return (((values[2] >> (width - 1)) ^ values[3]) & 1) if kind == 0 else ((values[0] >> (width - 1)) & 1 if kind == 1 else 0)


def _get_flag(state: EvaluatorStateV1, index: int) -> int:
    return ((state.eflags >> 4) & 1) if index == 6 else state.flags[_FLAGS[index]]


def _set_flag(state: EvaluatorStateV1, index: int, value: int) -> None:
    if index == 6: state.eflags = (state.eflags & ~(1 << 4)) | ((value & 1) << 4)
    else: state.flags[_FLAGS[index]] = value & 1


def _sync_eflags(state: EvaluatorStateV1) -> None:
    for name, bit in {"cf": 0, "pf": 2, "zf": 6, "sf": 7, "df": 10, "of": 11}.items():
        state.eflags = (state.eflags & ~(1 << bit)) | (state.flags[name] << bit)


def _repeat_move(state: EvaluatorStateV1, memory: EvaluatorMemoryV1, source: int, destination: int, count: int, direction: int, width: int) -> None:
    if width not in {1, 2, 4}: raise _SemanticFault
    step = -width if direction else width; state.registers.update(esi=source, edi=destination, ecx=count)
    while count:
        memory.write(destination, width, memory.read(source, width)); source, destination, count = _u32(source + step), _u32(destination + step), count - 1; state.registers.update(esi=source, edi=destination, ecx=count)


def _repeat_store(state: EvaluatorStateV1, memory: EvaluatorMemoryV1, destination: int, value: int, count: int, direction: int, width: int) -> None:
    if width not in {1, 2, 4}: raise _SemanticFault
    step = -width if direction else width; state.registers.update(edi=destination, ecx=count)
    while count:
        memory.write(destination, width, value); destination, count = _u32(destination + step), count - 1; state.registers.update(edi=destination, ecx=count)


def _repeat_scan(state: EvaluatorStateV1, memory: EvaluatorMemoryV1, accumulator: int, destination: int, count: int, direction: int) -> None:
    al, step = accumulator & 0xFF, (-1 if direction else 1); state.registers.update(edi=destination, ecx=count)
    while count:
        item = memory.read(destination, 1); result = (al - item) & 0xFF; destination, count = _u32(destination + step), count - 1; state.registers.update(edi=destination, ecx=count)
        state.flags.update(cf=int(al < item), zf=int(not result), sf=(result >> 7) & 1, of=int(((al ^ item) & (al ^ result) & 0x80) != 0), pf=int(result.bit_count() % 2 == 0)); _set_flag(state, 6, ((al ^ item ^ result) >> 4) & 1); _sync_eflags(state)
        if not result: break


__all__ = [
    "EvaluatorMemoryV1", "EvaluatorStateV1", "compare_observations",
    "evaluate_transfer_plan_case", "generated_differential_cases",
    "inspect_transfer_plan", "minimize_mismatch_case",
]
