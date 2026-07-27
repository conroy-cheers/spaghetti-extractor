from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

import z3

from ..relational.build import stage_a_build_relational
from ..relational.schema import RELATIONAL_APPROVED_AXIOMS
from ..relational.lean.definitions import _lean_counterexample_source
from ..stage_binary import StageAInputError, _parse_stage_a_pe
from ..util import sha256_file, write_json
from .model import (
    CaseManifest,
    _exact_fields,
    _identifier,
    _integer,
    _nonempty_string,
    _object,
    _sha256,
    _string_tuple,
)


VIOLATION_WITNESS_FORMAT = "stage-a-violation-witness-v2"
VIOLATION_CHECK_FORMAT = "stage-a-violation-check-v2"
AUTOMATIC_VIOLATION_DERIVATION_FORMAT = (
    "stage-a-automatic-violation-derivation-v1"
)
_HEX_BYTES_RE = re.compile(r"(?:[0-9a-f]{2})+")
_MISMATCH_KINDS = frozenset({
    "register_relation",
    "flag_relation",
    "memory_write_relation",
    "branch_destination",
    "external_event",
    "termination",
    "fault",
})

_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_MODELED_FLAG_BITS = (0, 2, 4, 6, 7, 10, 11)
_DIRECT_CONTROL_OPERATIONS = {"jump": 1, "branch": 2, "call": 3}
_FLAG_FIELDS = {
    "carry": 0,
    "parity": 2,
    "auxiliary": 4,
    "zero": 6,
    "sign": 7,
    "overflow": 11,
}
_ROUNDTRIP_STACK_BASE = 0x70000000
_ROUNDTRIP_INITIAL_ESP = _ROUNDTRIP_STACK_BASE + 2048
_MAX_REACHABILITY_STEPS = 64

# A writable JSON audit is not proof authority.  This process-local capability
# is installed only after the Lean kernel has checked the exact source tree.
# Warm artifacts loaded by a later process are replayed below.
_FRESH_KERNEL_REPLAYS: dict[str, tuple[str, str]] = {}


@dataclass(frozen=True)
class _MismatchClaim:
    kind: str
    relation_atom: str
    observation: str
    original_location: str
    candidate_location: str
    original_value: Any
    candidate_value: Any
    condition: Any
    effect_kind: str = "word"


@dataclass(frozen=True)
class _SymbolicPathState:
    registers: dict[str, Any]
    flags: dict[int, Any]
    memory: Any


@dataclass(frozen=True)
class _SymbolicPathStep:
    region_index: int
    original_outcome: Mapping[str, Any]
    candidate_outcome: Mapping[str, Any]


@dataclass(frozen=True)
class _ReachableCandidate:
    path: tuple[_SymbolicPathStep, ...]
    original_state: _SymbolicPathState
    candidate_state: _SymbolicPathState
    constraints: tuple[Any, ...]
    memory_reads: tuple[Any, ...]


class _UnsupportedViolationFragment(Exception):
    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


class _ConcreteProposalSemantics:
    """Untrusted QF_BV/array witness proposal semantics.

    Lean independently decodes and evaluates the same exact region before the
    proposal can become a checked violation.
    """

    def __init__(
        self, prefix: str, memory: Any, *, state: _SymbolicPathState | None = None,
    ) -> None:
        self.registers = (
            dict(state.registers)
            if state is not None else {
                register: z3.BitVec(f"{prefix}_{register}", 32)
                for register in _REGISTERS
            }
        )
        self.flags = (
            dict(state.flags)
            if state is not None else {
                bit: z3.Bool(f"{prefix}_flag_{bit}")
                for bit in _MODELED_FLAG_BITS
            }
        )
        self.memory = state.memory if state is not None else memory
        self.memory_reads: list[Any] = []

    def expression(self, payload: Any) -> Any:
        if not isinstance(payload, Mapping):
            self._unsupported("expression_not_object", payload)
        operation = payload.get("op")
        if operation == "input_reg":
            register = payload.get("reg")
            if register not in self.registers:
                self._unsupported("unknown_input_register", payload)
            return self.registers[str(register)]
        if operation == "input_flag_value":
            bit = payload.get("bit")
            if bit not in self.flags:
                self._unsupported("unsupported_input_flag", payload)
            return z3.If(
                self.flags[int(bit)], z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)
            )
        if operation == "bool_to_word":
            return z3.If(
                self.boolean(payload.get("value")),
                z3.BitVecVal(1, 32),
                z3.BitVecVal(0, 32),
            )
        if operation == "constant":
            value = payload.get("value")
            if not isinstance(value, int) or isinstance(value, bool):
                self._unsupported("invalid_constant", payload)
            return z3.BitVecVal(int(value) & 0xFFFFFFFF, 32)
        if operation in {
            "add", "sub", "bit_and", "bit_xor", "bit_or", "multiply",
            "shift_left_by", "shift_right_by", "shift_arithmetic_right_by",
        }:
            left = self.expression(payload.get("left"))
            right = self.expression(payload.get("right"))
            masked = right & z3.BitVecVal(31, 32)
            return {
                "add": lambda: left + right,
                "sub": lambda: left - right,
                "bit_and": lambda: left & right,
                "bit_xor": lambda: left ^ right,
                "bit_or": lambda: left | right,
                "multiply": lambda: left * right,
                "shift_left_by": lambda: left << masked,
                "shift_right_by": lambda: z3.LShR(left, masked),
                "shift_arithmetic_right_by": lambda: left >> masked,
            }[str(operation)]()
        if operation == "bit_not":
            return ~self.expression(payload.get("value"))
        if operation in {"shift_left", "shift_right"}:
            amount = payload.get("amount")
            if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                self._unsupported("invalid_constant_shift", payload)
            value = self.expression(payload.get("value"))
            return value << amount if operation == "shift_left" else z3.LShR(
                value, amount
            )
        if operation == "extract_byte":
            index = payload.get("index")
            if not isinstance(index, int) or not 0 <= index < 4:
                self._unsupported("invalid_byte_index", payload)
            value = self.expression(payload.get("value"))
            return z3.ZeroExt(24, z3.Extract(index * 8 + 7, index * 8, value))
        if operation == "bit_value":
            index = payload.get("index")
            if not isinstance(index, int) or not 0 <= index < 32:
                self._unsupported("invalid_bit_index", payload)
            value = self.expression(payload.get("value"))
            return z3.If(
                z3.Extract(index, index, value) == z3.BitVecVal(1, 1),
                z3.BitVecVal(1, 32),
                z3.BitVecVal(0, 32),
            )
        if operation == "if_equal":
            return z3.If(
                self.expression(payload.get("left"))
                == self.expression(payload.get("right")),
                self.expression(payload.get("then")),
                self.expression(payload.get("else")),
            )
        if operation == "unsigned_less_value":
            return z3.If(
                z3.ULT(
                    self.expression(payload.get("left")),
                    self.expression(payload.get("right")),
                ),
                z3.BitVecVal(1, 32),
                z3.BitVecVal(0, 32),
            )
        if operation in {"read8", "read32"}:
            address = self.expression(payload.get("address"))
            self.memory_reads.append(address)
            if operation == "read8":
                return z3.ZeroExt(24, z3.Select(self.memory, address))
            bytes_ = [
                z3.Select(self.memory, address + z3.BitVecVal(offset, 32))
                for offset in range(4)
            ]
            return z3.Concat(bytes_[3], bytes_[2], bytes_[1], bytes_[0])
        if operation == "read8_after_write":
            address = self.expression(payload.get("address"))
            write_address = self.expression(payload.get("write_address"))
            write_value = self.expression(payload.get("write_value"))
            prior = self.expression(payload.get("prior"))
            return z3.If(
                address == write_address,
                z3.ZeroExt(24, z3.Extract(7, 0, write_value)),
                prior,
            )
        self._unsupported("unsupported_expression", payload)

    def boolean(self, payload: Any) -> Any:
        if not isinstance(payload, Mapping):
            self._unsupported("boolean_not_object", payload)
        operation = payload.get("op")
        if operation == "bool_constant":
            if not isinstance(payload.get("value"), bool):
                self._unsupported("invalid_boolean_constant", payload)
            return z3.BoolVal(bool(payload["value"]))
        if operation == "input_flag":
            index = payload.get("index")
            if index not in self.flags:
                self._unsupported("unsupported_input_flag", payload)
            return self.flags[int(index)]
        if operation == "not":
            return z3.Not(self.boolean(payload.get("value")))
        if operation in {"and", "or", "xor"}:
            left = self.boolean(payload.get("left"))
            right = self.boolean(payload.get("right"))
            return {
                "and": lambda: z3.And(left, right),
                "or": lambda: z3.Or(left, right),
                "xor": lambda: z3.Xor(left, right),
            }[str(operation)]()
        if operation in {"equal", "unsigned_less"}:
            left = self.expression(payload.get("left"))
            right = self.expression(payload.get("right"))
            return left == right if operation == "equal" else z3.ULT(left, right)
        if operation in {"msb", "bit"}:
            index = 31 if operation == "msb" else payload.get("index")
            if not isinstance(index, int) or not 0 <= index < 32:
                self._unsupported("invalid_boolean_bit_index", payload)
            value = self.expression(payload.get("value"))
            return z3.Extract(index, index, value) == z3.BitVecVal(1, 1)
        self._unsupported("unsupported_boolean_expression", payload)

    @staticmethod
    def _unsupported(reason_code: str, payload: Any) -> None:
        operation = payload.get("op") if isinstance(payload, Mapping) else None
        raise _UnsupportedViolationFragment(
            reason_code,
            f"automatic violation derivation does not support semantic operation "
            f"{operation!r}",
        )


def _initial_symbolic_path_states(memory: Any) -> tuple[
    _SymbolicPathState, _SymbolicPathState, tuple[Any, ...]
]:
    original = _ConcreteProposalSemantics("launch_original", memory)
    candidate = _ConcreteProposalSemantics("launch_candidate", memory)
    constraints: list[Any] = [
        original.registers[register] == candidate.registers[register]
        for register in _REGISTERS
    ]
    constraints.extend(
        original.flags[bit] == candidate.flags[bit] for bit in _MODELED_FLAG_BITS
    )
    constraints.extend((
        original.registers["esp"] == z3.BitVecVal(_ROUNDTRIP_INITIAL_ESP, 32),
        candidate.registers["esp"] == z3.BitVecVal(_ROUNDTRIP_INITIAL_ESP, 32),
    ))
    return (
        _SymbolicPathState(original.registers, original.flags, memory),
        _SymbolicPathState(candidate.registers, candidate.flags, memory),
        tuple(constraints),
    )


def _execute_symbolic_region(
    *, prefix: str, state: _SymbolicPathState, ir: Mapping[str, Any],
) -> tuple[_SymbolicPathState, Mapping[str, Any], tuple[Any, ...]]:
    semantics = _ConcreteProposalSemantics(prefix, state.memory, state=state)
    registers_payload = ir.get("registers")
    writes_payload = ir.get("writes")
    flags_payload = ir.get("flags")
    outcome_payload = ir.get("outcome")
    if not isinstance(registers_payload, Mapping):
        raise _UnsupportedViolationFragment(
            "register_outputs_missing", "reachable path region omits register outputs"
        )
    if not isinstance(writes_payload, list) or not isinstance(flags_payload, Mapping):
        raise _UnsupportedViolationFragment(
            "path_effects_missing", "reachable path region omits writes or flags"
        )
    if not isinstance(outcome_payload, Mapping):
        raise _UnsupportedViolationFragment(
            "path_outcome_missing", "reachable path region omits its control outcome"
        )
    next_registers = {
        register: semantics.expression(registers_payload[register])
        for register in _REGISTERS
    }
    next_memory = state.memory
    for write in writes_payload:
        if not isinstance(write, Mapping):
            raise _UnsupportedViolationFragment(
                "malformed_memory_write", "reachable path writes must be objects"
            )
        address = semantics.expression(write.get("address"))
        value = semantics.expression(write.get("value"))
        for offset in range(4):
            byte = z3.Extract(offset * 8 + 7, offset * 8, value)
            next_memory = z3.Store(
                next_memory, address + z3.BitVecVal(offset, 32), byte
            )
    next_flags = dict(state.flags)
    for field, bit in _FLAG_FIELDS.items():
        expression = flags_payload.get(field)
        if expression is not None:
            next_flags[bit] = semantics.boolean(expression)
    outcome = _evaluate_symbolic_outcome(outcome_payload, semantics)
    return (
        _SymbolicPathState(next_registers, next_flags, next_memory),
        outcome,
        tuple(semantics.memory_reads),
    )


def _evaluate_symbolic_outcome(
    payload: Mapping[str, Any], semantics: _ConcreteProposalSemantics,
) -> Mapping[str, Any]:
    operation = payload.get("op")
    if operation == "jump":
        return {"kind": "jump", "target": _target_id(payload.get("target"))}
    if operation == "branch":
        return {
            "kind": "branch",
            "condition": semantics.boolean(payload.get("condition")),
            "taken": _target_id(payload.get("taken")),
            "fallthrough": _target_id(payload.get("fallthrough")),
        }
    if operation == "call":
        return {
            "kind": "call",
            "target": _target_id(payload.get("target")),
            "continuation": _target_id(payload.get("continuation")),
        }
    if operation == "returned":
        return {
            "kind": "returned",
            "target": semantics.expression(payload.get("target")),
        }
    raise _UnsupportedViolationFragment(
        "unsupported_reachability_outcome",
        f"reachable negative path does not support outcome {operation!r}",
    )


def _target_id(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _UnsupportedViolationFragment(
            "invalid_reachability_target", "reachable path target must be a target ID"
        )
    return int(value)


def _target_region_map(contract: Mapping[str, Any]) -> dict[int, int]:
    targets = contract.get("code_targets")
    if not isinstance(targets, list):
        raise _UnsupportedViolationFragment(
            "code_target_inventory_missing", "relation contract omits code targets"
        )
    result: dict[int, int] = {}
    for row in targets:
        if not isinstance(row, Mapping):
            raise _UnsupportedViolationFragment(
                "malformed_code_target", "relation code targets must be objects"
            )
        target_id = _target_id(row.get("id"))
        region_index = _target_id(row.get("region_index"))
        if target_id in result:
            raise _UnsupportedViolationFragment(
                "ambiguous_code_target", "relation code target IDs must be unique"
            )
        result[target_id] = region_index
    return result


def _reachable_symbolic_candidates(
    *, contract: Mapping[str, Any], decoded_regions: list[Any], target_index: int,
    memory: Any,
) -> tuple[_ReachableCandidate, ...]:
    regions = contract.get("regions")
    if not isinstance(regions, list):
        raise _UnsupportedViolationFragment(
            "malformed_prepared_regions", "relation contract omits regions"
        )
    roots = [
        index for index, row in enumerate(regions)
        if isinstance(row, Mapping) and row.get("root") is True
    ]
    if len(roots) != 1:
        raise _UnsupportedViolationFragment(
            "launch_root_not_unique",
            f"structured negative proof requires one PE entry root, found {len(roots)}",
        )
    target_regions = _target_region_map(contract)
    original_initial, candidate_initial, initial_constraints = (
        _initial_symbolic_path_states(memory)
    )
    results: list[_ReachableCandidate] = []

    def visit(
        region_index: int,
        original_state: _SymbolicPathState,
        candidate_state: _SymbolicPathState,
        constraints: tuple[Any, ...],
        calls: tuple[int, ...],
        path: tuple[_SymbolicPathStep, ...],
        reads: tuple[Any, ...],
    ) -> None:
        if len(path) > _MAX_REACHABILITY_STEPS or len(results) >= 16:
            return
        if region_index == target_index:
            results.append(_ReachableCandidate(
                path, original_state, candidate_state, constraints, reads
            ))
            return
        if not 0 <= region_index < len(decoded_regions):
            return
        row = decoded_regions[region_index]
        if not isinstance(row, Mapping):
            return
        original_ir = row.get("original_ir")
        candidate_ir = row.get("candidate_ir")
        if not isinstance(original_ir, Mapping) or not isinstance(candidate_ir, Mapping):
            return
        next_original, original_outcome, original_reads = _execute_symbolic_region(
            prefix=f"path_o_{len(path)}", state=original_state, ir=original_ir
        )
        next_candidate, candidate_outcome, candidate_reads = _execute_symbolic_region(
            prefix=f"path_c_{len(path)}", state=candidate_state, ir=candidate_ir
        )
        if original_outcome["kind"] != candidate_outcome["kind"]:
            return
        kind = str(original_outcome["kind"])
        alternatives: list[tuple[int, tuple[Any, ...], tuple[int, ...]]] = []
        if kind == "jump":
            if original_outcome["target"] == candidate_outcome["target"]:
                next_region = target_regions.get(int(original_outcome["target"]))
                if next_region is not None:
                    alternatives.append((next_region, (), calls))
        elif kind == "branch":
            arms = (("taken", True), ("fallthrough", False))
            for original_arm, original_guard in arms:
                for candidate_arm, candidate_guard in arms:
                    original_target = original_outcome[original_arm]
                    candidate_target = candidate_outcome[candidate_arm]
                    if original_target != candidate_target:
                        continue
                    next_region = target_regions.get(int(original_target))
                    if next_region is not None:
                        alternatives.append((
                            next_region,
                            (
                                original_outcome["condition"]
                                == z3.BoolVal(original_guard),
                                candidate_outcome["condition"]
                                == z3.BoolVal(candidate_guard),
                            ),
                            calls,
                        ))
        elif kind == "call":
            if (
                original_outcome["target"] == candidate_outcome["target"]
                and original_outcome["continuation"]
                    == candidate_outcome["continuation"]
            ):
                next_region = target_regions.get(int(original_outcome["target"]))
                if next_region is not None:
                    alternatives.append((
                        next_region, (), (int(original_outcome["continuation"]), *calls)
                    ))
        elif kind == "returned" and calls:
            continuation = calls[0]
            next_region = target_regions.get(continuation)
            target_row = next(
                (
                    row for row in contract.get("code_targets", [])
                    if isinstance(row, Mapping) and row.get("id") == continuation
                ),
                None,
            )
            if next_region is not None and isinstance(target_row, Mapping):
                original_word = int(target_row["original_rva"]) + int(
                    _parse_contract_image_base(contract, "original")
                )
                candidate_word = int(target_row["candidate_rva"]) + int(
                    _parse_contract_image_base(contract, "candidate")
                )
                alternatives.append((
                    next_region,
                    (
                        original_outcome["target"] == z3.BitVecVal(original_word, 32),
                        candidate_outcome["target"] == z3.BitVecVal(candidate_word, 32),
                    ),
                    calls[1:],
                ))
        for next_region, guards, next_calls in alternatives:
            solver = z3.Solver()
            solver.add(*constraints, *guards)
            if solver.check() != z3.sat:
                continue
            visit(
                next_region,
                next_original,
                next_candidate,
                (*constraints, *guards),
                next_calls,
                (*path, _SymbolicPathStep(
                    region_index, original_outcome, candidate_outcome
                )),
                (*reads, *original_reads, *candidate_reads),
            )

    visit(
        roots[0], original_initial, candidate_initial, initial_constraints, (), (), ()
    )
    return tuple(results)


def _parse_contract_image_base(contract: Mapping[str, Any], side: str) -> int:
    # Return paths need the concrete address pushed by CALL.  StaticProofContext
    # remains Lean authority; this untrusted helper only proposes the witness.
    model = contract.get("model")
    if isinstance(model, Mapping):
        value = model.get(f"{side}_image_base")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return 0x400000


def derive_concrete_violation_witness(
    *,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
) -> dict[str, Any]:
    """Propose a deterministic witness for the checked concrete fragment.

    This function has no verdict authority. Its successful output is explicitly
    marked as requiring Lean replay; unsupported or witness-free cases are
    returned as ``incomplete``.
    """

    try:
        witness = _derive_concrete_violation_witness(
            case=case,
            case_root=Path(case_root),
            prepared=Path(prepared),
        )
    except _UnsupportedViolationFragment as exc:
        return {
            "format": AUTOMATIC_VIOLATION_DERIVATION_FORMAT,
            "status": "incomplete",
            "reason_code": exc.reason_code,
            "detail": exc.detail,
            "witness": None,
            "trust": {
                "role": "untrusted_witness_proposal",
                "can_authorize_violated": False,
                "requires_lean_replay": True,
            },
        }
    return {
        "format": AUTOMATIC_VIOLATION_DERIVATION_FORMAT,
        "status": "ready_for_lean_replay",
        "reason_code": None,
        "detail": None,
        "witness": witness.to_payload(),
        "trust": {
            "role": "untrusted_witness_proposal",
            "can_authorize_violated": False,
            "requires_lean_replay": True,
        },
    }


def _derive_concrete_violation_witness(
    *,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
) -> "ViolationWitness":
    if case.mutation is None or case.expectation.witness_family is None:
        raise _UnsupportedViolationFragment(
            "missing_supported_mutation",
            "automatic violation derivation requires an expected-violated mutation",
        )
    relation_path = prepared / "relation-contract.json"
    decoded_path = prepared / "relational-decoded-behaviors.json"
    if not relation_path.is_file() or not decoded_path.is_file():
        raise _UnsupportedViolationFragment(
            "prepared_semantics_missing",
            "automatic violation derivation requires the normalized contract and decoded semantics",
        )
    contract = _load_object(relation_path, "normalized relation contract")
    decoded = _load_object(decoded_path, "decoded behaviors")
    if contract.get("format") != "stage-a-relation-contract-v1":
        raise _UnsupportedViolationFragment(
            "unsupported_relation_contract",
            "automatic violation derivation requires stage-a-relation-contract-v1",
        )
    if decoded.get("format") != "stage-a-relational-decoded-behaviors-v1":
        raise _UnsupportedViolationFragment(
            "unsupported_decoded_semantics",
            "automatic violation derivation requires normalized decoded behavior v1",
        )

    original_path = case.artifact("original_pe").verify(case_root)
    candidate_path = case.artifact("candidate_pe").verify(case_root)
    original_bin = _parse_stage_a_pe(original_path)
    candidate_bin = _parse_stage_a_pe(candidate_path)
    expected_bindings = {
        "original_sha256": original_bin.sha256,
        "candidate_sha256": candidate_bin.sha256,
        "relation_contract_sha256": sha256_file(relation_path),
    }
    for field, expected in expected_bindings.items():
        observed = decoded.get(field)
        if observed is not None and observed != expected:
            raise _UnsupportedViolationFragment(
                "stale_prepared_semantics",
                f"decoded behavior {field} does not bind the current prepared input",
            )

    regions = contract.get("regions")
    decoded_regions = decoded.get("regions")
    if not isinstance(regions, list) or not isinstance(decoded_regions, list):
        raise _UnsupportedViolationFragment(
            "malformed_prepared_regions",
            "prepared contract and decoded semantics must contain region lists",
        )
    if len(regions) != len(decoded_regions):
        raise _UnsupportedViolationFragment(
            "prepared_region_count_mismatch",
            "prepared contract and decoded semantics have different region counts",
        )
    location_id = case.mutation.location_id
    matches = [
        index
        for index, region in enumerate(regions)
        if isinstance(region, Mapping)
        and _semantic_location_matches_region(location_id, region)
    ]
    if len(matches) > 1:
        rooted_matches = [
            index
            for index in matches
            if isinstance(regions[index], Mapping)
            and regions[index].get("root") is True
        ]
        if len(rooted_matches) == 1:
            matches = rooted_matches
    if len(matches) != 1:
        raise _UnsupportedViolationFragment(
            "semantic_location_not_unique",
            f"mutation location {location_id!r} matched {len(matches)} prepared regions",
        )
    region_index = matches[0]
    region = regions[region_index]
    decoded_region = decoded_regions[region_index]
    if not isinstance(region, Mapping) or not isinstance(decoded_region, Mapping):
        raise _UnsupportedViolationFragment(
            "malformed_prepared_region", "the selected prepared region is malformed"
        )
    if decoded_region.get("index") != region_index:
        raise _UnsupportedViolationFragment(
            "noncanonical_decoded_region", "decoded region indices are not canonical"
        )
    original_ir = decoded_region.get("original_ir")
    candidate_ir = decoded_region.get("candidate_ir")
    if not isinstance(original_ir, Mapping) or not isinstance(candidate_ir, Mapping):
        raise _UnsupportedViolationFragment(
            "decoded_ir_missing", "the selected region omits normalized semantic IR"
        )
    for side, ir in (("original", original_ir), ("candidate", candidate_ir)):
        if ir.get("format") != "stage-a-normalized-behavior-v1":
            raise _UnsupportedViolationFragment(
                "unsupported_normalized_behavior",
                f"{side} behavior is not stage-a-normalized-behavior-v1",
            )
        expected_ir_hash = decoded_region.get(f"{side}_ir_sha256")
        if expected_ir_hash is not None and expected_ir_hash != _canonical_sha256(ir):
            raise _UnsupportedViolationFragment(
                "stale_decoded_ir",
                f"{side} normalized behavior hash does not match its payload",
            )
        if not isinstance(decoded_region.get(f"{side}_term"), str):
            raise _UnsupportedViolationFragment(
                "decoded_lean_term_missing",
                f"{side} decoded behavior omits its exact Lean term",
            )

    _require_exact_concrete_input_fragment(region)
    memory = z3.Array(
        "violation_memory", z3.BitVecSort(32), z3.BitVecSort(8)
    )
    reachable_candidates = _reachable_symbolic_candidates(
        contract=contract,
        decoded_regions=decoded_regions,
        target_index=region_index,
        memory=memory,
    )
    selected: tuple[
        _MismatchClaim, Any, _ReachableCandidate,
        _ConcreteProposalSemantics, _ConcreteProposalSemantics,
    ] | None = None
    for reachable in reachable_candidates:
        original_semantics = _ConcreteProposalSemantics(
            "target_original", memory, state=reachable.original_state
        )
        candidate_semantics = _ConcreteProposalSemantics(
            "target_candidate", memory, state=reachable.candidate_state
        )
        claims = _mismatch_claims(
            region=region,
            original_ir=original_ir,
            candidate_ir=candidate_ir,
            original_semantics=original_semantics,
            candidate_semantics=candidate_semantics,
            original_image_base=original_bin.image_base,
            candidate_image_base=candidate_bin.image_base,
        )
        for claim in claims:
            solver = z3.Solver()
            solver.set("random_seed", 0)
            solver.add(*reachable.constraints, claim.condition)
            result = solver.check()
            if result == z3.sat:
                selected = (
                    claim, solver.model(), reachable,
                    original_semantics, candidate_semantics,
                )
                break
            if result == z3.unknown:
                raise _UnsupportedViolationFragment(
                    "witness_solver_unknown",
                    "untrusted reachable witness solver returned unknown: "
                    f"{solver.reason_unknown()}",
                )
        if selected is not None:
            break
    if selected is None:
        raise _UnsupportedViolationFragment(
            "no_supported_reachable_mismatch",
            "no launch-reachable mismatch in the supported register, memory-write, "
            "or direct-control fragment was found",
        )
    claim, model, reachable, original_semantics, candidate_semantics = selected
    memory_words = _model_memory_words(
        model,
        memory,
        (
            *reachable.memory_reads,
            *original_semantics.memory_reads,
            *candidate_semantics.memory_reads,
        ),
    )
    original_state = _concrete_state_from_model(
        model=model,
        semantics=original_semantics,
        memory_words=memory_words,
        path_guard=str(region.get("id")),
    )
    original_launch_state = _concrete_symbolic_path_state(
        model=model,
        state=_initial_symbolic_path_states(memory)[0],
        memory_words=(),
        path_guards=("pe32-entrypoint",),
    )
    candidate_launch_state = _concrete_symbolic_path_state(
        model=model,
        state=_initial_symbolic_path_states(memory)[1],
        memory_words=(),
        path_guards=("pe32-entrypoint",),
    )
    candidate_state = _concrete_state_from_model(
        model=model,
        semantics=candidate_semantics,
        memory_words=memory_words,
        path_guard=str(region.get("id")),
    )
    original_effect_value = _model_word(model, claim.original_value)
    candidate_effect_value = _model_word(model, claim.candidate_value)
    if original_effect_value == candidate_effect_value:
        raise _UnsupportedViolationFragment(
            "proposal_effect_not_distinct",
            "the selected model did not produce distinct concrete effects",
        )
    original_location = _semantic_location(
        semantic_id=location_id,
        region_index=region_index,
        region=region,
        side="original",
        binary=original_bin,
        path=(case.template, location_id, str(region.get("id"))),
    )
    candidate_location = _semantic_location(
        semantic_id=location_id,
        region_index=region_index,
        region=region,
        side="candidate",
        binary=candidate_bin,
        path=(case.template, location_id, str(region.get("id"))),
    )
    bindings = BinaryBindings(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        relation_contract_sha256=sha256_file(relation_path),
        decoded_behaviors_sha256=sha256_file(decoded_path),
        capability_profile=case.capability_profile,
    )
    mismatch = Mismatch(
        kind=claim.kind,
        relation_atom=claim.relation_atom,
        original_effect=MismatchEffect(
            kind=claim.effect_kind,
            location=claim.original_location,
            value=original_effect_value,
        ),
        candidate_effect=MismatchEffect(
            kind=claim.effect_kind,
            location=claim.candidate_location,
            value=candidate_effect_value,
        ),
        observation=claim.observation,
        event_index=None,
    )
    reachability = _materialize_reachability_witness(
        model=model,
        contract=contract,
        decoded_regions=decoded_regions,
        reachable=reachable,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        original_launch_state=original_launch_state,
        candidate_launch_state=candidate_launch_state,
        target_region_index=region_index,
    )
    stable_body = {
        "case_id": case.id,
        "mutation": case.mutation.to_payload(),
        "bindings": bindings.to_payload(),
        "region_index": region_index,
        "reachability": reachability.to_payload(),
        "original_pre_state": original_state.to_payload(),
        "candidate_pre_state": candidate_state.to_payload(),
        "mismatch": mismatch.to_payload(),
    }
    digest = _canonical_sha256(stable_body)[:20]
    witness = ViolationWitness(
        id=f"violation-{case.mutation.id}-{digest}",
        obligation_id=(
            f"segment:{region.get('id')}:{claim.kind}:"
            f"{claim.original_location}:{digest}"
        ),
        family=case.expectation.witness_family,
        bindings=bindings,
        location=WitnessLocation(original=original_location, candidate=candidate_location),
        reachability=reachability,
        original_pre_state=original_state,
        candidate_pre_state=candidate_state,
        mismatch=mismatch,
        replay=case.replay,
    )
    return ViolationWitness.parse(witness.to_payload())


def _semantic_location_matches_region(
    location_id: str, region: Mapping[str, Any],
) -> bool:
    """Resolve a generator semantic block through untrusted source-map names.

    This is witness-location proposal logic only.  The selected bytes and
    decoded behavior are subsequently bound and checked by Lean.
    """

    identities = {
        str(region.get("id") or ""),
        str(region.get("function_id") or ""),
    }
    if location_id in identities:
        return True
    normalized = location_id.replace("-", "_").lstrip("_")
    aliases = {f"rt_{normalized}", f"_rt_{normalized}"}
    if location_id == "entry":
        aliases.update({"mainCRTStartup", "_mainCRTStartup"})
    return bool(identities & aliases)


def produce_checked_violation(
    *,
    witness_path: Path | None = None,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
    out: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
    build: bool = True,
) -> dict[str, Any]:
    """Replay a proposed concrete mismatch through exact Lean PE semantics."""

    case_root = Path(case_root)
    prepared = Path(prepared)
    out = Path(out)
    automatic_derivation: dict[str, Any] | None = None
    if witness_path is None:
        automatic_derivation = derive_concrete_violation_witness(
            case=case, case_root=case_root, prepared=prepared
        )
        if automatic_derivation["status"] != "ready_for_lean_replay":
            if out.exists():
                shutil.rmtree(out)
            out.mkdir(parents=True)
            derivation_path = out / "derivation.json"
            write_json(derivation_path, automatic_derivation)
            return {
                "format": "stage-a-violation-production-v1",
                "status": "incomplete",
                "reason_code": automatic_derivation["reason_code"],
                "derivation": str(derivation_path),
                "audit": None,
                "source": None,
                "lean": None,
            }
        witness = ViolationWitness.parse(automatic_derivation["witness"])
        effective_witness_path: Path | None = None
    else:
        effective_witness_path = Path(witness_path)
        witness = ViolationWitness.parse(
            _load_object(effective_witness_path, "violation witness")
        )
    _validate_witness_input_bindings(
        witness=witness,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    if witness.location.original.region_index != witness.location.candidate.region_index:
        raise StageAInputError(
            "violation replay currently requires one paired relation region"
        )
    region_index = witness.location.original.region_index
    contract = _load_object(
        prepared / "relation-contract.json", "normalized relation contract"
    )
    decoded = _load_object(
        prepared / "relational-decoded-behaviors.json", "decoded behaviors"
    )
    regions = contract.get("regions")
    decoded_regions = decoded.get("regions")
    if not isinstance(regions, list) or region_index >= len(regions):
        raise StageAInputError("violation witness region is outside the relation contract")
    if not isinstance(decoded_regions, list) or region_index >= len(decoded_regions):
        raise StageAInputError("violation witness region is outside decoded behaviors")
    region = regions[region_index]
    decoded_region = decoded_regions[region_index]
    if not isinstance(region, dict) or not isinstance(decoded_region, dict):
        raise StageAInputError("violation replay region records are malformed")
    if decoded_region.get("index") != region_index:
        raise StageAInputError("decoded violation region index is not canonical")
    original_term = decoded_region.get("original_term")
    candidate_term = decoded_region.get("candidate_term")
    if not isinstance(original_term, str) or not isinstance(candidate_term, str):
        raise StageAInputError("decoded violation region omits Lean behavior terms")
    for side, location in (
        ("original", witness.location.original),
        ("candidate", witness.location.candidate),
    ):
        span = region.get(side)
        if (
            not isinstance(span, dict)
            or location.rva != span.get("rva_start")
            or len(bytes.fromhex(location.bytes_hex)) != span.get("size")
        ):
            raise StageAInputError(
                f"violation {side} location must bind the complete relation region"
            )
    assignment = {
        f"{side_prefix}{register}": value
        for side_prefix, state in (
            ("o", witness.original_pre_state),
            ("c", witness.candidate_pre_state),
        )
        for register, value in state.registers
    }
    original_binary_path = case.artifact("original_pe").verify(case_root)
    candidate_binary_path = case.artifact("candidate_pe").verify(case_root)
    original_bin = _parse_stage_a_pe(original_binary_path)
    candidate_bin = _parse_stage_a_pe(candidate_binary_path)
    source = _lean_counterexample_source(
        original_bin,
        candidate_bin,
        original_binary_path.read_bytes(),
        candidate_binary_path.read_bytes(),
        contract.get("code_targets", []),
        contract.get("machine_import_call_contracts", []),
        region,
        region_index,
        {"original": original_term, "candidate": candidate_term},
        assignment,
        original_state=witness.original_pre_state.to_payload(),
        candidate_state=witness.candidate_pre_state.to_payload(),
    )
    source = _append_classified_mismatch_theorem(
        source=source, witness=witness, region_index=region_index
    )
    source = _append_reachable_mismatch_theorem(
        source=source, witness=witness, region_index=region_index
    )
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    if automatic_derivation is not None:
        derivation_path = out / "derivation.json"
        write_json(derivation_path, automatic_derivation)
        effective_witness_path = out / "witness.json"
        write_json(effective_witness_path, witness.to_payload())
    assert effective_witness_path is not None
    counterexample_prepared = out / "prepared-proof"
    source_path = _prepare_counterexample_module(
        prepared=prepared,
        destination=counterexample_prepared,
        source=source,
    )
    if not build:
        return {
            "format": "stage-a-violation-production-v1",
            "status": "ready",
            "audit": None,
            "witness": str(effective_witness_path),
            "source": str(source_path),
            "source_sha256": sha256_file(source_path),
            "prepared": str(counterexample_prepared),
            "lean": None,
        }
    checked = stage_a_build_relational(
        prepared=counterexample_prepared,
        out=out / "nix-node",
        flake=flake,
        builders_file=builders_file,
        target_nodes=["relationalcounterexample"],
    )
    combined = _focused_node_lean_output(out / "nix-node", checked)
    observed_axioms: set[str] = set()
    for match in re.findall(r"depends on axioms: \[(.*?)\]", combined, re.DOTALL):
        observed_axioms.update(
            item.strip()
            for item in match.replace("\n", " ").split(",")
            if item.strip()
        )
    unexpected_axioms = sorted(observed_axioms - RELATIONAL_APPROVED_AXIOMS)
    axiom_audit_seen = (
        "reachableExactCounterexample" in combined
        and (
            "depends on axioms:" in combined
            or "does not depend on any axioms" in combined
        )
    )
    audit = {
        "format": VIOLATION_CHECK_FORMAT,
        "status": (
            "checked"
            if checked.get("status") == "checked" and axiom_audit_seen
            else "incomplete"
        ),
        "witness_sha256": sha256_file(effective_witness_path),
        "theorem": (
            "StageA.GeneratedRelationalCounterexample."
            "reachableExactCounterexample"
        ),
        "mismatch_theorem": (
            "StageA.GeneratedRelationalCounterexample."
            "reachableClassifiedMismatchChecked"
        ),
        "mismatch_kind": witness.mismatch.kind,
        "reachability_sha256": _canonical_sha256(
            witness.reachability.to_payload()
        ),
        "proof_source_sha256": sha256(source.encode("utf-8")).hexdigest(),
        "lean_trust": 0,
        "observed_axioms": sorted(observed_axioms),
        "unexpected_axioms": unexpected_axioms,
        "decoded_behaviors_sha256": sha256_file(
            prepared / "relational-decoded-behaviors.json"
        ),
        "original_sha256": original_bin.sha256,
        "candidate_sha256": candidate_bin.sha256,
    }
    out.mkdir(parents=True, exist_ok=True)
    audit_path = out / "audit.json"
    write_json(audit_path, audit)
    if audit["status"] == "checked" and not unexpected_axioms:
        _FRESH_KERNEL_REPLAYS[str(audit_path.resolve())] = (
            sha256_file(audit_path), sha256_file(effective_witness_path)
        )
    return {
        "format": "stage-a-violation-production-v1",
        "status": audit["status"],
        "audit": str(audit_path),
        "witness": str(effective_witness_path),
        "source": str(source_path),
        "source_sha256": sha256_file(source_path),
        "lean": checked,
    }


def _prepare_counterexample_module(
    *, prepared: Path, destination: Path, source: str,
) -> Path:
    """Add one counterexample leaf to an otherwise immutable prepared graph."""

    shutil.copytree(prepared, destination, copy_function=shutil.copy2)
    source_path = destination / "lean" / "StageA" / "RelationalCounterexample.lean"
    source_path.write_text(source, encoding="utf-8")
    source_digest = sha256_file(source_path)
    graph_path = destination / "module-graph.json"
    # The ordinary build entry point remains authoritative for graph validity.
    # This early return keeps source-generation fixtures small while a real
    # invocation still fails closed in ``stage_a_build_relational``.
    if not graph_path.is_file():
        return source_path
    graph = dict(_load_object(graph_path, "relational module graph"))
    modules = graph.get("modules")
    nodes = graph.get("nodes")
    auxiliary_modules = graph.get("auxiliary_modules")
    counts = graph.get("counts")
    if (
        not isinstance(modules, dict)
        or not isinstance(nodes, list)
        or not isinstance(auxiliary_modules, list)
        or not isinstance(counts, dict)
    ):
        raise StageAInputError("relational module graph is malformed")
    if "RelationalCounterexample" in modules or any(
        isinstance(node, dict) and node.get("id") == "relationalcounterexample"
        for node in nodes
    ):
        raise StageAInputError("prepared proof already defines a counterexample node")
    required_imports = (
        "RelationalLaunchRealizabilityCertificate",
        "RelationalRegionChunks",
    )
    missing_imports = [module for module in required_imports if module not in modules]
    if missing_imports:
        raise StageAInputError(
            "prepared proof omits counterexample dependencies: "
            + ", ".join(missing_imports)
        )
    dependency_owners: dict[str, str] = {}
    for required_module in required_imports:
        owners = [
            node.get("id")
            for node in nodes
            if isinstance(node, dict)
            and isinstance(node.get("modules"), list)
            and required_module in node["modules"]
            and isinstance(node.get("id"), str)
        ]
        if len(owners) != 1:
            raise StageAInputError(
                f"counterexample dependency {required_module!r} must have one node owner"
            )
        dependency_owners[required_module] = owners[0]
    modules["RelationalCounterexample"] = {
        "imports": list(required_imports),
        "source": "lean/StageA/RelationalCounterexample.lean",
        "source_bytes": source_path.stat().st_size,
        "source_sha256": source_digest,
    }
    nodes.append({
        "dependencies": sorted(set(dependency_owners.values())),
        "estimated_memory_mb": 512,
        "id": "relationalcounterexample",
        "modules": ["RelationalCounterexample"],
        "resource_class": "light",
        "source_sha256": source_digest,
    })
    auxiliary_modules.append("RelationalCounterexample")
    for field in ("derivations", "logical_modules"):
        value = counts.get(field)
        if not isinstance(value, int):
            raise StageAInputError(f"relational module graph omits count {field}")
        counts[field] = value + 1
    write_json(graph_path, graph)
    prepared_manifest_path = destination / "prepared-proof.json"
    prepared_manifest = dict(_load_object(
        prepared_manifest_path, "prepared proof manifest"
    ))
    prepared_manifest["module_graph_sha256"] = sha256_file(graph_path)
    prepared_counts = prepared_manifest.get("counts")
    if isinstance(prepared_counts, dict):
        for field in ("derivations", "logical_modules"):
            value = prepared_counts.get(field)
            if isinstance(value, int):
                prepared_counts[field] = value + 1
    write_json(prepared_manifest_path, prepared_manifest)
    return source_path


def _focused_node_lean_output(node_out: Path, checked: Mapping[str, Any]) -> str:
    """Read compiler diagnostics emitted by the content-addressed node build."""

    chunks: list[str] = []
    node = checked.get("node")
    if isinstance(node, Mapping):
        for field in ("lean_stdout", "lean_stderr", "compiler_output"):
            value = node.get(field)
            if isinstance(value, str):
                chunks.append(value)
    for pattern in ("*.stdout", "*.stderr", "*.log"):
        for path in sorted(node_out.rglob(pattern)):
            if path.is_file():
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def prepare_checked_violation_nix_input(
    *, case: CaseManifest, case_root: Path, prepared: Path, out: Path,
) -> dict[str, Any]:
    """Materialize a counterexample-augmented prepared graph for one Nix node.

    Witness discovery remains untrusted.  This phase only binds the proposed
    witness to exact prepared artifacts and adds the Lean replay leaf; the
    result has no authority until that leaf has been compiled and audited.
    """

    out = Path(out)
    with tempfile.TemporaryDirectory(prefix="stage-a-violation-prepare-") as temporary:
        production = produce_checked_violation(
            case=case,
            case_root=case_root,
            prepared=prepared,
            out=Path(temporary) / "replay",
            build=False,
        )
        if production.get("status") != "ready":
            raise StageAInputError(
                "negative case could not produce a checked-violation replay input: "
                + str(production.get("reason_code") or production.get("status"))
            )
        augmented = Path(str(production["prepared"]))
        witness = Path(str(production["witness"]))
        if out.exists():
            shutil.rmtree(out)
        shutil.copytree(augmented, out, copy_function=shutil.copy2)
        shutil.copy2(witness, out / "violation-witness.json")
        derivation = Path(temporary) / "replay" / "derivation.json"
        if derivation.is_file():
            shutil.copy2(derivation, out / "violation-derivation.json")
    replay = {
        "format": "stage-a-violation-nix-input-v1",
        "status": "ready",
        "case_id": case.id,
        "witness_sha256": sha256_file(out / "violation-witness.json"),
        "counterexample_source_sha256": sha256_file(
            out / "lean" / "StageA" / "RelationalCounterexample.lean"
        ),
        "module_graph_sha256": sha256_file(out / "module-graph.json"),
        "acceptance_authority": False,
    }
    write_json(out / "violation-replay-input.json", replay)
    return replay


def audit_prebuilt_checked_violation(
    *,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
    proof_node: Path,
    out: Path,
) -> dict[str, Any]:
    """Audit a Nix-built counterexample leaf and emit the checked result."""

    prepared = Path(prepared)
    proof_node = Path(proof_node)
    out = Path(out)
    witness_path = prepared / "violation-witness.json"
    witness = ViolationWitness.parse(_load_object(witness_path, "violation witness"))
    _validate_witness_input_bindings(
        witness=witness,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    graph = _load_object(prepared / "module-graph.json", "relational module graph")
    nodes = graph.get("nodes")
    modules = graph.get("modules")
    if not isinstance(nodes, list) or not isinstance(modules, Mapping):
        raise StageAInputError("relational module graph is malformed")
    expected_nodes = [
        node for node in nodes
        if isinstance(node, Mapping) and node.get("id") == "relationalcounterexample"
    ]
    module_metadata = modules.get("RelationalCounterexample")
    if len(expected_nodes) != 1 or not isinstance(module_metadata, Mapping):
        raise StageAInputError("prepared proof omits its unique counterexample node")
    expected_node = expected_nodes[0]
    node_result_path = proof_node / "module-result.json"
    if not node_result_path.is_file():
        bundled_results = []
        for path in sorted((proof_node / "node-results").glob("*.json")):
            payload = _load_object(path, "bundled Lean node result")
            if payload.get("id") == "relationalcounterexample":
                bundled_results.append((path, payload))
        if len(bundled_results) != 1:
            raise StageAInputError(
                "Lean proof output must contain exactly one counterexample node result"
            )
        node_result_path, node_result = bundled_results[0]
    else:
        node_result = _load_object(node_result_path, "Lean node result")
    outputs = node_result.get("outputs")
    if not isinstance(outputs, list):
        raise StageAInputError("counterexample node result omits output inventory")
    counterexample_outputs = [
        item for item in outputs
        if isinstance(item, Mapping) and item.get("module") == "RelationalCounterexample"
    ]
    if len(counterexample_outputs) != 1:
        raise StageAInputError("counterexample node result has an invalid module inventory")
    output = counterexample_outputs[0]
    axiom_audit = output.get("axiom_audit")
    if not isinstance(axiom_audit, Mapping):
        raise StageAInputError("counterexample node result omits its axiom audit")
    requested = axiom_audit.get("requested")
    inventories = axiom_audit.get("inventories")
    if not isinstance(requested, list) or not isinstance(inventories, Mapping):
        raise StageAInputError("counterexample axiom audit is malformed")
    required_theorem = "reachableExactCounterexample"
    observed = inventories.get(required_theorem)
    source_path = proof_node / "StageA" / "RelationalCounterexample.lean"
    olean_path = proof_node / "StageA" / "RelationalCounterexample.olean"
    source_sha256 = sha256_file(source_path) if source_path.is_file() else ""
    olean_sha256 = sha256_file(olean_path) if olean_path.is_file() else ""
    expected_source_sha256 = module_metadata.get("source_sha256")
    node_checked = (
        graph.get("lean", {}).get("trust") == 0
        and node_result.get("format") == "stage-a-lean-node-result-v1"
        and node_result.get("id") == "relationalcounterexample"
        and node_result.get("source_sha256") == expected_node.get("source_sha256")
        and source_sha256 == expected_source_sha256
        and output.get("olean_sha256") == olean_sha256
        and isinstance(output.get("olean_bytes"), int)
        and output.get("olean_bytes", 0) > 0
        and axiom_audit.get("complete") is True
        and required_theorem in requested
        and isinstance(observed, list)
    )
    observed_axioms = sorted(set(observed or []))
    unexpected_axioms = sorted(set(observed_axioms) - RELATIONAL_APPROVED_AXIOMS)
    original_binary_path = case.artifact("original_pe").verify(case_root)
    candidate_binary_path = case.artifact("candidate_pe").verify(case_root)
    audit = {
        "format": VIOLATION_CHECK_FORMAT,
        "status": "checked" if node_checked and not unexpected_axioms else "incomplete",
        "witness_sha256": sha256_file(witness_path),
        "theorem": (
            "StageA.GeneratedRelationalCounterexample."
            "reachableExactCounterexample"
        ),
        "mismatch_theorem": (
            "StageA.GeneratedRelationalCounterexample."
            "reachableClassifiedMismatchChecked"
        ),
        "mismatch_kind": witness.mismatch.kind,
        "reachability_sha256": _canonical_sha256(witness.reachability.to_payload()),
        "proof_source_sha256": source_sha256,
        "lean_trust": 0 if node_checked else 1,
        "observed_axioms": observed_axioms,
        "unexpected_axioms": unexpected_axioms,
        "decoded_behaviors_sha256": sha256_file(
            prepared / "relational-decoded-behaviors.json"
        ),
        "original_sha256": sha256_file(original_binary_path),
        "candidate_sha256": sha256_file(candidate_binary_path),
    }
    result = _validate_checked_violation_audit(
        witness=witness,
        witness_path=witness_path,
        audit=audit,
        audit_provenance="nix-counterexample-node",
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    write_json(out / "audit.json", audit)
    write_json(out / "violation-audit.json", result)
    return {
        "format": "stage-a-violation-nix-audit-v1",
        "status": result["status"],
        "audit": str(out / "audit.json"),
        "result": str(out / "violation-audit.json"),
    }


def _append_classified_mismatch_theorem(
    *, source: str, witness: "ViolationWitness", region_index: int,
) -> str:
    family_expression = {
        "register_relation": (
            f"registersRelatedValues originalPe.imageBase candidatePe.imageBase "
            f"region{region_index}.targets region{region_index}.values "
            f"region{region_index}.outputs originalResult.registers "
            "candidateResult.registers"
        ),
        "memory_write_relation": (
            f"writesRelated originalPe.imageBase candidatePe.imageBase "
            f"region{region_index}.targets region{region_index}.values "
            "originalResult.writes candidateResult.writes"
        ),
        "branch_destination": (
            f"outcomesRelated originalPe.imageBase candidatePe.imageBase "
            f"region{region_index}.targets region{region_index}.values "
            "originalResult.outcome candidateResult.outcome"
        ),
    }.get(witness.mismatch.kind)
    if family_expression is None:
        raise StageAInputError(
            "automatic checked violation does not support the declared mismatch family"
        )
    theorem = (
        "def classifiedMismatch : Bool :=\n"
        f"  match evalBehavior false region{region_index}.targets originalState "
        "originalBehavior,\n"
        f"      evalBehavior true region{region_index}.targets candidateState "
        "candidateBehavior with\n"
        "  | some originalResult, some candidateResult =>\n"
        f"      !({family_expression})\n"
        "  | _, _ => false\n\n"
        "theorem classifiedMismatchChecked : classifiedMismatch = true := by decide\n\n"
        "#print axioms classifiedMismatchChecked\n\n"
    )
    marker = "#print axioms exactCounterexample\n\n"
    if marker not in source:
        raise StageAInputError(
            "generated counterexample source omits its theorem audit marker"
        )
    return source.replace(marker, marker + theorem, 1)


def _append_reachable_mismatch_theorem(
    *, source: str, witness: "ViolationWitness", region_index: int,
) -> str:
    reachability = witness.reachability
    if reachability.target_region_index != region_index:
        raise StageAInputError("reachable counterexample target does not match its region")
    source = source.replace(
        "import StageA.Relational\n",
        "import StageA.RelationalLaunchRealizabilityCertificate\n"
        "import StageA.RelationalRegionChunks\n",
        1,
    )
    open_marker = "open StageA.Formal StageA.Relational\n\n"
    if open_marker not in source:
        raise StageAInputError("generated counterexample source omits its namespace imports")
    source = source.replace(
        open_marker,
        open_marker + "open StageA.GeneratedRelational\n\n",
        1,
    )
    original_launch = _lean_reachable_launch_state(
        "original", reachability.original_launch_state
    )
    candidate_launch = _lean_reachable_launch_state(
        "candidate", reachability.candidate_launch_state
    )
    path_source, original_target_state, candidate_target_state = _lean_path_source(
        reachability
    )
    family_expression = _lean_reachable_family_expression(
        witness, region_index, original_target_state, candidate_target_state
    )
    effect_expression = _lean_reported_effect_expression(witness)
    theorem = (
        original_launch
        + candidate_launch
        + _LEAN_REACHABLE_LAUNCH_PROOF
        + path_source
        + _lean_outcome_diagnostic_definition(witness)
        + f"def reachableOriginalResult : Option RelationalBehavior :=\n"
        + f"  evalBehavior false region{region_index}.targets "
        + f"{original_target_state} originalBehavior\n\n"
        + f"def reachableCandidateResult : Option RelationalBehavior :=\n"
        + f"  evalBehavior true region{region_index}.targets "
        + f"{candidate_target_state} candidateBehavior\n\n"
        + "def reachableClassifiedMismatch : Bool :=\n"
        + "  match reachableOriginalResult, reachableCandidateResult with\n"
        + "  | some originalResult, some candidateResult =>\n"
        + f"      !({family_expression})\n"
        + "  | _, _ => false\n\n"
        + "def reportedMismatchValuesMatch : Bool :=\n"
        + "  match reachableOriginalResult, reachableCandidateResult with\n"
        + "  | some originalResult, some candidateResult =>\n"
        + f"      {effect_expression}\n"
        + "  | _, _ => false\n\n"
        + "theorem reachableClassifiedMismatchChecked :\n"
        + "    reachableClassifiedMismatch = true := by decide\n\n"
        + "theorem reportedMismatchValuesChecked :\n"
        + "    reportedMismatchValuesMatch = true := by decide\n\n"
        + "theorem reachableExactCounterexample :\n"
        + "    consoleLaunch.LinkedStatesRelated staticProofContext "
        + "relationalProductGraph relationalProductReachabilityEvidence "
        + "linkedProductControlProfile consoleLaunchWorld "
        + "reachableOriginalLaunchState reachableCandidateLaunchState ∧\n"
        + "    originalReachabilityChecked = true ∧\n"
        + "    candidateReachabilityChecked = true ∧\n"
        + f"    regionBehaviorWithMachineCallContracts originalPe originalImports "
        + f"machineImportCallContracts region{region_index}.original = "
        + "some originalBehavior ∧\n"
        + f"    regionBehaviorWithMachineCallContracts candidatePe candidateImports "
        + f"machineImportCallContracts region{region_index}.candidate = "
        + "some candidateBehavior ∧\n"
        + "    reachableClassifiedMismatch = true ∧\n"
        + "    reportedMismatchValuesMatch = true := by\n"
        + "  exact ⟨reachableLaunchAdmissible, by decide, by decide, "
        + "originalBehaviorCachedDecoded, candidateBehaviorCachedDecoded, "
        + "reachableClassifiedMismatchChecked, reportedMismatchValuesChecked⟩\n\n"
        + "#print axioms reachableExactCounterexample\n\n"
    )
    end_marker = "end StageA.GeneratedRelationalCounterexample\n"
    if end_marker not in source:
        raise StageAInputError("generated counterexample source omits its namespace end")
    return source.replace(end_marker, theorem + end_marker, 1)


def _lean_reachable_launch_state(side: str, state: "ConcreteState") -> str:
    prefix = "o" if side == "original" else "c"
    base = (
        "consoleLaunchOriginalState" if side == "original"
        else "consoleLaunchCandidateState"
    )
    fields = ", ".join(
        f"{register} := BitVec.ofNat 32 {value}"
        for register, value in state.registers
    )
    return (
        f"def reachable{side.title()}LaunchRegisters : Registers Word := "
        + "{ " + fields + " }\n\n"
        + f"def reachable{side.title()}LaunchState : MachineState := "
        + f"{{ {base} with registers := reachable{side.title()}LaunchRegisters, "
        + f"eflags := BitVec.ofNat 32 {state.eflags} }}\n\n"
    )


_LEAN_REACHABLE_LAUNCH_PROOF = """theorem reachableLaunchStateRelated :
    StateRel staticProofContext consoleLaunchWorld consoleLaunch.rootInvariant
      reachableOriginalLaunchState reachableCandidateLaunchState := by
  refine ⟨consoleLaunchWorldValid.1, by decide, ?_, by decide, by decide,
    ?_, ?_, ?_, ?_, ?_⟩
  · exact consoleLaunchStackMemoryRelated
  · apply importAddressesMemoryHold_of_checked
    decide
  · exact consoleLaunchOriginalImmutableImage
  · exact consoleLaunchCandidateImmutableImage
  · refine ⟨by decide, by decide, by decide, by decide, ?_, ?_, rfl, ?_,
      by decide, rfl⟩
    · exact ordinaryMemoryRelated_projection_of_mapped_identity
        staticProofContext consoleLaunchWorld
        staticProofContext.codeMap.entries.toList
        (staticProofContext.relationalValueTargets consoleLaunchWorld)
        consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory
        (by decide)
    · refine { staticPointerSlots := ?_, staticWordSlots := ?_, active := ?_ }
      · intro slot member
        simp [staticProofContext] at member
      · exact consoleLaunchStaticWordSlotsRelated
      · exact { registerRanges := by decide, stackRanges := by decide }
    · simp [MachineX87Related, reachableOriginalLaunchState,
        reachableCandidateLaunchState, consoleLaunchOriginalState,
        consoleLaunchCandidateState, StageA.Relational.X87.StateRelated,
        StageA.Relational.X87.MetadataRelated, StageA.X87.PhysicalState.core,
        StageA.X87.PhysicalState.metadata, x87AddressRelation]
  · decide

theorem reachableLaunchAdmissible :
    consoleLaunch.LinkedStatesRelated staticProofContext relationalProductGraph
      relationalProductReachabilityEvidence linkedProductControlProfile
      consoleLaunchWorld reachableOriginalLaunchState
      reachableCandidateLaunchState := by
  refine ⟨consoleLaunchFrames, [], consoleLaunchWorldValid,
    consoleLaunchOriginalImageMapped, consoleLaunchCandidateImageMapped,
    ?_, ?_, ?_, ?_, ?_, reachableLaunchStateRelated⟩
  · simp [consoleLaunch, consoleLaunchFrames, reachableOriginalLaunchState,
      reachableCandidateLaunchState, consoleLaunchOriginalState,
      consoleLaunchCandidateState, consoleLaunchOriginalMemory,
      consoleLaunchCandidateMemory, consoleLaunchCandidateExcludedMemory,
      consoleLaunchOriginalWrites, consoleLaunchCandidateWrites,
      RelationalLinkedRuntimeCallStackHolds,
      PE32ConsoleLaunchV2.continuationTargetIds] <;> decide
  · exact LinkedProductControlProfile.LinksAllowed.nil
      linkedProductControlProfile linkedProductControlProfileChecked
  · simp [consoleLaunch, RelationalLinkedRuntimeCallFactsHold]
  · exact RelationalRuntimeCallTargetsMapped.of_checked
      relationalProductGraph relationalProductReachabilityEvidence
      [] consoleLaunch.continuationTargetIds (by decide)
  · simp [consoleLaunch, consoleLaunchFrames, reachableOriginalLaunchState,
      reachableCandidateLaunchState, consoleLaunchOriginalState,
      consoleLaunchCandidateState, consoleLaunchOriginalMemory,
      consoleLaunchCandidateMemory, consoleLaunchCandidateExcludedMemory,
      consoleLaunchOriginalWrites, consoleLaunchCandidateWrites,
      PE32TlsProcessAttachArgumentsHold] <;> decide

"""


def _lean_path_source(
    reachability: "ReachabilityWitness",
) -> tuple[str, str, str]:
    rows: list[str] = []
    final_states: list[str] = []
    for side, steps in (
        ("Original", reachability.original_steps),
        ("Candidate", reachability.candidate_steps),
    ):
        candidate = "true" if side == "Candidate" else "false"
        state_name = f"reachable{side}LaunchState"
        checks: list[str] = []
        for index, step in enumerate(steps):
            result_name = f"reachable{side}PathResult{index}"
            next_state = f"reachable{side}PathState{index + 1}"
            region = f"StageA.GeneratedRelational.region{step.region_index}"
            behavior = (
                f"StageA.GeneratedRelational.{'candidate' if side == 'Candidate' else 'original'}"
                f"Behavior{step.region_index}"
            )
            expected = _lean_outcome(step.selected_outcome)
            rows.append(
                f"def {result_name} : Option RelationalBehavior :=\n"
                f"  evalBehavior {candidate} {region}.targets {state_name} {behavior}\n\n"
                f"def {next_state} : MachineState :=\n"
                f"  match {result_name} with\n"
                f"  | some result => result.nextMachineState {state_name}\n"
                f"  | none => {state_name}\n\n"
            )
            decoded = (
                f"decide (regionBehaviorWithMachineCallContracts "
                f"staticProofContext.{'candidatePe' if side == 'Candidate' else 'originalPe'} "
                f"staticProofContext.{'candidateImports' if side == 'Candidate' else 'originalImports'} "
                f"staticProofContext.machineImportCallContracts {region}."
                f"{'candidate' if side == 'Candidate' else 'original'} = some {behavior})"
            )
            checks.append(
                f"({decoded} && match {result_name} with | some result => "
                f"decide (result.outcome = {expected}) | none => false)"
            )
            state_name = next_state
        root_region = f"StageA.GeneratedRelational.region{reachability.root_region_index}"
        root_pe = (
            "staticProofContext.candidatePe" if side == "Candidate"
            else "staticProofContext.originalPe"
        )
        root_span = "candidate" if side == "Candidate" else "original"
        root_check = (
            f"decide ({root_region}.root = true ∧ "
            f"{root_region}.{root_span}.start = {root_pe}.entrypointRva)"
        )
        all_checks = " && ".join((root_check, *checks)) or root_check
        rows.append(
            f"def {side.lower()}ReachabilityChecked : Bool :=\n  {all_checks}\n\n"
        )
        final_states.append(state_name)
    return "".join(rows), final_states[0], final_states[1]


def _lean_outcome(payload: Mapping[str, Any]) -> str:
    kind = payload["kind"]
    if kind == "jump":
        return f".jump {int(payload['target'])}"
    if kind == "branch":
        condition = "true" if payload["condition"] else "false"
        return (
            f".branch {condition} {int(payload['taken'])} "
            f"{int(payload['fallthrough'])}"
        )
    if kind == "call":
        return f".call {int(payload['target'])} {int(payload['continuation'])}"
    if kind == "returned":
        return f".returned (BitVec.ofNat 32 {int(payload['target'])})"
    raise StageAInputError("reachable witness contains an unsupported outcome")


def _lean_reachable_family_expression(
    witness: "ViolationWitness", region_index: int,
    original_state: str, candidate_state: str,
) -> str:
    return {
        "register_relation": (
            f"registersRelatedValues originalPe.imageBase candidatePe.imageBase "
            f"region{region_index}.targets region{region_index}.values "
            f"region{region_index}.outputs originalResult.registers "
            "candidateResult.registers"
        ),
        "memory_write_relation": (
            f"writesRelated originalPe.imageBase candidatePe.imageBase "
            f"region{region_index}.targets region{region_index}.values "
            "originalResult.writes candidateResult.writes"
        ),
        "branch_destination": (
            f"outcomesRelated originalPe.imageBase candidatePe.imageBase "
            f"region{region_index}.targets region{region_index}.values "
            "originalResult.outcome candidateResult.outcome"
        ),
    }.get(witness.mismatch.kind) or "false"


def _lean_reported_effect_expression(witness: "ViolationWitness") -> str:
    original = _lean_effect_expression(
        "originalResult", witness.mismatch.original_effect
    )
    candidate = _lean_effect_expression(
        "candidateResult", witness.mismatch.candidate_effect
    )
    return (
        f"({original} == some (BitVec.ofNat 32 "
        f"{witness.mismatch.original_effect.value})) && "
        f"({candidate} == some (BitVec.ofNat 32 "
        f"{witness.mismatch.candidate_effect.value}))"
    )


def _lean_effect_expression(result: str, effect: "MismatchEffect") -> str:
    location = effect.location
    if effect.kind == "word" and location in _REGISTERS:
        return f"some {result}.registers.{location}"
    match = re.fullmatch(r"writes\[(\d+)\]\.(address|value)", location)
    if effect.kind == "word" and match:
        projection = ".1" if match.group(2) == "address" else ".2"
        return f"({result}.writes[{int(match.group(1))}]?).map (fun row => row{projection})"
    if effect.kind == "word" and location == "writes.length":
        return f"some (BitVec.ofNat 32 {result}.writes.length)"
    if effect.kind == "control_target":
        return f"reachableOutcomeDiagnostic {result}.outcome"
    raise StageAInputError(
        "reachable mismatch does not support the proposed diagnostic effect"
    )


def _lean_outcome_diagnostic_definition(witness: "ViolationWitness") -> str:
    if witness.mismatch.original_effect.kind != "control_target":
        return ""
    location = witness.mismatch.original_effect.location
    if location == "outcome.selected-target":
        body = (
            "  | .branch condition taken fallthrough =>\n"
            "      some (BitVec.ofNat 32 (if condition then taken else fallthrough))\n"
        )
    elif location == "outcome.target":
        body = (
            "  | .jump target => some (BitVec.ofNat 32 target)\n"
            "  | .call target _ => some (BitVec.ofNat 32 target)\n"
        )
    elif location == "outcome.continuation":
        body = "  | .call _ continuation => some (BitVec.ofNat 32 continuation)\n"
    elif location == "outcome.kind":
        body = (
            "  | .jump _ => some (BitVec.ofNat 32 1)\n"
            "  | .branch _ _ _ => some (BitVec.ofNat 32 2)\n"
            "  | .call _ _ => some (BitVec.ofNat 32 3)\n"
        )
    else:
        raise StageAInputError("reachable control diagnostic location is unsupported")
    return (
        "def reachableOutcomeDiagnostic : PureOutcome -> Option Word\n"
        + body
        + "  | _ => none\n\n"
    )


def _require_exact_concrete_input_fragment(region: Mapping[str, Any]) -> None:
    unsupported_nonempty = (
        "bounds",
        "address_separations",
        "input_dynamic_range_relations",
        "input_dynamic_stack_range_relations",
        "input_import_relations",
    )
    for field in unsupported_nonempty:
        value = region.get(field, [])
        if value not in (None, []):
            raise _UnsupportedViolationFragment(
                "unsupported_input_relation",
                f"automatic violation derivation does not yet support nonempty {field}",
            )
    for field in ("input_relations", "output_relations"):
        relations = region.get(field, [])
        if not isinstance(relations, list) or any(
            not isinstance(row, Mapping) for row in relations
        ):
            raise _UnsupportedViolationFragment(
                "malformed_relation_inventory",
                f"region {field} must be a list of relation objects",
            )
    for field in ("inputs", "outputs", "flag_inputs", "flag_outputs"):
        if not isinstance(region.get(field, []), list):
            raise _UnsupportedViolationFragment(
                "malformed_relation_inventory", f"region {field} must be a list"
            )


def _related_input_constraints(
    *,
    region: Mapping[str, Any],
    original: _ConcreteProposalSemantics,
    candidate: _ConcreteProposalSemantics,
) -> list[Any]:
    # The same-name equalities choose a small deterministic subset of valid
    # exact states. Explicit input pairs additionally cover register-renamed
    # regions without treating the proposal as proof authority.
    constraints = [
        original.registers[register] == candidate.registers[register]
        for register in _REGISTERS
    ]
    for pair in region.get("inputs", []):
        if not isinstance(pair, Mapping):
            raise _UnsupportedViolationFragment(
                "malformed_input_pair", "region input pairs must be objects"
            )
        original_register = pair.get("original")
        candidate_register = pair.get("candidate")
        if (
            original_register not in original.registers
            or candidate_register not in candidate.registers
        ):
            raise _UnsupportedViolationFragment(
                "unsupported_input_register", "region input pair names an unknown register"
            )
        constraints.append(
            original.registers[str(original_register)]
            == candidate.registers[str(candidate_register)]
        )
    constraints.extend(
        original.flags[bit] == candidate.flags[bit]
        for bit in _MODELED_FLAG_BITS
    )
    return constraints


def _mismatch_claims(
    *,
    region: Mapping[str, Any],
    original_ir: Mapping[str, Any],
    candidate_ir: Mapping[str, Any],
    original_semantics: _ConcreteProposalSemantics,
    candidate_semantics: _ConcreteProposalSemantics,
    original_image_base: int,
    candidate_image_base: int,
) -> list[_MismatchClaim]:
    claims: list[_MismatchClaim] = []
    original_registers = original_ir.get("registers")
    candidate_registers = candidate_ir.get("registers")
    if not isinstance(original_registers, Mapping) or not isinstance(
        candidate_registers, Mapping
    ):
        raise _UnsupportedViolationFragment(
            "register_outputs_missing", "normalized behavior omits register outputs"
        )
    output_relations = region.get("outputs", [])
    for pair in sorted(
        output_relations,
        key=lambda row: (str(row.get("original")), str(row.get("candidate"))),
    ):
        original_register = pair.get("original")
        candidate_register = pair.get("candidate")
        if (
            original_register not in original_registers
            or candidate_register not in candidate_registers
        ):
            raise _UnsupportedViolationFragment(
                "register_output_missing",
                "an exact output relation names a missing normalized register",
            )
        original_value = original_semantics.expression(
            original_registers[str(original_register)]
        )
        candidate_value = candidate_semantics.expression(
            candidate_registers[str(candidate_register)]
        )
        claims.append(_MismatchClaim(
            kind="register_relation",
            relation_atom=(
                f"register-{original_register}-{candidate_register}-related-word"
            ),
            observation="register-state",
            original_location=str(original_register),
            candidate_location=str(candidate_register),
            original_value=original_value,
            candidate_value=candidate_value,
            condition=z3.Not(_word_related_condition(
                region=region,
                original_image_base=original_image_base,
                candidate_image_base=candidate_image_base,
                original=original_value,
                candidate=candidate_value,
            )),
        ))

    original_writes = original_ir.get("writes")
    candidate_writes = candidate_ir.get("writes")
    if not isinstance(original_writes, list) or not isinstance(candidate_writes, list):
        raise _UnsupportedViolationFragment(
            "memory_writes_missing", "normalized behavior writes must be lists"
        )
    if len(original_writes) != len(candidate_writes):
        claims.append(_MismatchClaim(
            kind="memory_write_relation",
            relation_atom="memory-write-count-exact",
            observation="memory-write",
            original_location="writes.length",
            candidate_location="writes.length",
            original_value=z3.BitVecVal(len(original_writes), 32),
            candidate_value=z3.BitVecVal(len(candidate_writes), 32),
            condition=z3.BoolVal(True),
        ))
    for index, (original_write, candidate_write) in enumerate(
        zip(original_writes, candidate_writes, strict=False)
    ):
        if not isinstance(original_write, Mapping) or not isinstance(
            candidate_write, Mapping
        ):
            raise _UnsupportedViolationFragment(
                "malformed_memory_write", "normalized memory writes must be objects"
            )
        for field in ("address", "value"):
            original_value = original_semantics.expression(original_write.get(field))
            candidate_value = candidate_semantics.expression(candidate_write.get(field))
            claims.append(_MismatchClaim(
                kind="memory_write_relation",
                relation_atom=f"memory-write-{field}-exact",
                observation="memory-write",
                original_location=f"writes[{index}].{field}",
                candidate_location=f"writes[{index}].{field}",
                original_value=original_value,
                candidate_value=candidate_value,
                condition=original_value != candidate_value,
            ))

    claims.extend(_direct_control_claims(
        original_ir.get("outcome"),
        candidate_ir.get("outcome"),
        original_semantics,
        candidate_semantics,
    ))
    if not claims:
        raise _UnsupportedViolationFragment(
            "empty_supported_fragment",
            "the selected region has no supported observable relation claims",
        )
    return claims


def _word_related_condition(
    *,
    region: Mapping[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    original: Any,
    candidate: Any,
) -> Any:
    """Mirror ``StageA.Relational.wordRelated`` for witness proposal only."""

    zero = z3.BitVecVal(0, 32)
    mapped_code: list[Any] = []
    targets = region.get("code_targets", [])
    if not isinstance(targets, list):
        raise _UnsupportedViolationFragment(
            "malformed_code_target", "region code targets must be a list"
        )
    for target in targets:
        if not isinstance(target, Mapping):
            raise _UnsupportedViolationFragment(
                "malformed_code_target", "region code targets must be objects"
            )
        original_addresses = _code_target_addresses(
            target, side="original", image_base=original_image_base
        )
        candidate_addresses = _code_target_addresses(
            target, side="candidate", image_base=candidate_image_base
        )
        mapped_code.append(z3.And(
            z3.Or(*(original == address for address in original_addresses)),
            z3.Or(*(candidate == address for address in candidate_addresses)),
        ))

    mapped_values: list[Any] = []
    values = region.get("values", [])
    if not isinstance(values, list):
        raise _UnsupportedViolationFragment(
            "malformed_value_target", "region value targets must be a list"
        )
    for target in values:
        if not isinstance(target, Mapping):
            raise _UnsupportedViolationFragment(
                "malformed_value_target", "region value targets must be objects"
            )
        original_base = _target_word_field(target, "original_value")
        candidate_base = _target_word_field(target, "candidate_value")
        mapped_size = _target_word_field(target, "mapped_size")
        exact_base = z3.And(
            original == z3.BitVecVal(original_base, 32),
            candidate == z3.BitVecVal(candidate_base, 32),
        )
        if mapped_size == 0:
            mapped_values.append(exact_base)
            continue
        candidate_base_word = z3.BitVecVal(candidate_base, 32)
        mapped_values.append(z3.Or(
            exact_base,
            z3.And(
                z3.ULE(candidate_base_word, candidate),
                z3.ULT(
                    candidate,
                    candidate_base_word + z3.BitVecVal(mapped_size, 32),
                ),
                original == z3.BitVecVal(original_base, 32)
                    + (candidate - candidate_base_word),
            ),
        ))

    return z3.And(
        (original == zero) == (candidate == zero),
        z3.Or(
            original == candidate,
            z3.Or(*mapped_code) if mapped_code else z3.BoolVal(False),
            z3.Or(*mapped_values) if mapped_values else z3.BoolVal(False),
        ),
    )


def _code_target_addresses(
    target: Mapping[str, Any], *, side: str, image_base: int,
) -> tuple[Any, ...]:
    primary = _target_word_field(target, f"{side}_rva")
    aliases = target.get(f"{side}_aliases", [])
    if not isinstance(aliases, list) or any(
        not isinstance(alias, int) or isinstance(alias, bool) or alias < 0
        for alias in aliases
    ):
        raise _UnsupportedViolationFragment(
            "malformed_code_target", f"region {side} code aliases are malformed"
        )
    return tuple(
        z3.BitVecVal((image_base + rva) & 0xFFFFFFFF, 32)
        for rva in (primary, *aliases)
    )


def _target_word_field(target: Mapping[str, Any], field: str) -> int:
    value = target.get(field)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < 2**32
    ):
        raise _UnsupportedViolationFragment(
            "malformed_value_target", f"region target {field} is not a 32-bit word"
        )
    return int(value)


def _direct_control_claims(
    original_payload: Any,
    candidate_payload: Any,
    original_semantics: _ConcreteProposalSemantics,
    candidate_semantics: _ConcreteProposalSemantics,
) -> list[_MismatchClaim]:
    if not isinstance(original_payload, Mapping) or not isinstance(
        candidate_payload, Mapping
    ):
        return []
    original_operation = original_payload.get("op")
    candidate_operation = candidate_payload.get("op")
    if (
        original_operation not in _DIRECT_CONTROL_OPERATIONS
        or candidate_operation not in _DIRECT_CONTROL_OPERATIONS
    ):
        return []
    if original_operation != candidate_operation:
        original_value = z3.BitVecVal(
            _DIRECT_CONTROL_OPERATIONS[str(original_operation)], 32
        )
        candidate_value = z3.BitVecVal(
            _DIRECT_CONTROL_OPERATIONS[str(candidate_operation)], 32
        )
        return [_MismatchClaim(
            kind="branch_destination",
            relation_atom="direct-control-kind-exact",
            observation="control-flow",
            original_location="outcome.kind",
            candidate_location="outcome.kind",
            original_value=original_value,
            candidate_value=candidate_value,
            condition=z3.BoolVal(True),
            effect_kind="control_target",
        )]

    fields: list[tuple[str, Any, Any]]
    if original_operation == "jump":
        fields = [("target", original_payload.get("target"), candidate_payload.get("target"))]
    elif original_operation == "branch":
        original_target = z3.If(
            original_semantics.boolean(original_payload.get("condition")),
            _direct_target_word(original_payload.get("taken")),
            _direct_target_word(original_payload.get("fallthrough")),
        )
        candidate_target = z3.If(
            candidate_semantics.boolean(candidate_payload.get("condition")),
            _direct_target_word(candidate_payload.get("taken")),
            _direct_target_word(candidate_payload.get("fallthrough")),
        )
        fields = [("selected-target", original_target, candidate_target)]
    else:
        fields = [
            ("target", original_payload.get("target"), candidate_payload.get("target")),
            (
                "continuation",
                original_payload.get("continuation"),
                candidate_payload.get("continuation"),
            ),
        ]
    claims = []
    for field, original_target, candidate_target in fields:
        original_value = (
            original_target
            if z3.is_expr(original_target)
            else _direct_target_word(original_target)
        )
        candidate_value = (
            candidate_target
            if z3.is_expr(candidate_target)
            else _direct_target_word(candidate_target)
        )
        claims.append(_MismatchClaim(
            kind="branch_destination",
            relation_atom=f"direct-control-{field}-mapped",
            observation="control-flow",
            original_location=f"outcome.{field}",
            candidate_location=f"outcome.{field}",
            original_value=original_value,
            candidate_value=candidate_value,
            condition=original_value != candidate_value,
            effect_kind="control_target",
        ))
    return claims


def _direct_target_word(value: Any) -> Any:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**32:
        raise _UnsupportedViolationFragment(
            "unsupported_control_target",
            "automatic control violation derivation requires finite direct target IDs",
        )
    return z3.BitVecVal(value, 32)


def _concrete_state_from_model(
    *,
    model: Any,
    semantics: _ConcreteProposalSemantics,
    memory_words: tuple[tuple[int, int], ...],
    path_guard: str,
) -> "ConcreteState":
    registers = tuple(
        (register, _model_word(model, semantics.registers[register]))
        for register in sorted(_REGISTERS)
    )
    eflags = 2
    for bit in _MODELED_FLAG_BITS:
        if z3.is_true(model.eval(semantics.flags[bit], model_completion=True)):
            eflags |= 1 << bit
    world_state_sha256 = sha256(b"stage-a-empty-relational-world-v1").hexdigest()
    return ConcreteState(
        registers=registers,
        eflags=eflags,
        memory_words=memory_words,
        path_guards=(_stable_path_identifier(path_guard),),
        world_state_sha256=world_state_sha256,
    )


def _concrete_symbolic_path_state(
    *, model: Any, state: _SymbolicPathState,
    memory_words: tuple[tuple[int, int], ...], path_guards: tuple[str, ...],
) -> "ConcreteState":
    registers = tuple(
        (register, _model_word(model, state.registers[register]))
        for register in sorted(_REGISTERS)
    )
    eflags = 0
    for bit in _MODELED_FLAG_BITS:
        if z3.is_true(model.eval(state.flags[bit], model_completion=True)):
            eflags |= 1 << bit
    return ConcreteState(
        registers=registers,
        eflags=eflags,
        memory_words=memory_words,
        path_guards=path_guards,
        world_state_sha256=sha256(b"stage-a-console-launch-world-v1").hexdigest(),
    )


def _materialize_reachability_witness(
    *,
    model: Any,
    contract: Mapping[str, Any],
    decoded_regions: list[Any],
    reachable: _ReachableCandidate,
    original_bin: Any,
    candidate_bin: Any,
    original_launch_state: "ConcreteState",
    candidate_launch_state: "ConcreteState",
    target_region_index: int,
) -> "ReachabilityWitness":
    regions = contract.get("regions")
    assert isinstance(regions, list)
    roots = [
        index for index, row in enumerate(regions)
        if isinstance(row, Mapping) and row.get("root") is True
    ]
    original_steps: list[ReachabilityStep] = []
    candidate_steps: list[ReachabilityStep] = []
    for index, symbolic_step in enumerate(reachable.path):
        next_region = (
            reachable.path[index + 1].region_index
            if index + 1 < len(reachable.path) else target_region_index
        )
        decoded = decoded_regions[symbolic_step.region_index]
        region = regions[symbolic_step.region_index]
        if not isinstance(decoded, Mapping) or not isinstance(region, Mapping):
            raise _UnsupportedViolationFragment(
                "malformed_reachability_region", "reachable region is malformed"
            )
        for side, binary, outcome, destination in (
            ("original", original_bin, symbolic_step.original_outcome, original_steps),
            ("candidate", candidate_bin, symbolic_step.candidate_outcome, candidate_steps),
        ):
            span = region.get(side)
            ir = decoded.get(f"{side}_ir")
            if not isinstance(span, Mapping) or not isinstance(ir, Mapping):
                raise _UnsupportedViolationFragment(
                    "malformed_reachability_region", "reachable span or IR is malformed"
                )
            rva = int(span["rva_start"])
            size = int(span["size"])
            raw = binary.pe.get_data(rva, size)
            if len(raw) != size:
                raise _UnsupportedViolationFragment(
                    "reachability_bytes_unavailable", "reachable path bytes are outside PE"
                )
            destination.append(ReachabilityStep(
                region_index=symbolic_step.region_index,
                rva=rva,
                bytes_hex=raw.hex(),
                decoded_ir_sha256=_canonical_sha256(ir),
                selected_outcome=_materialize_outcome(model, outcome, next_region),
                next_region_index=next_region,
            ))
    return ReachabilityWitness(
        launch_profile="pe32-console-launch-v1",
        root_region_index=roots[0],
        target_region_index=target_region_index,
        original_launch_state=original_launch_state,
        candidate_launch_state=candidate_launch_state,
        original_steps=tuple(original_steps),
        candidate_steps=tuple(candidate_steps),
    )


def _materialize_outcome(
    model: Any, outcome: Mapping[str, Any], next_region_index: int,
) -> Mapping[str, Any]:
    kind = str(outcome["kind"])
    if kind == "jump":
        return {"kind": kind, "target": int(outcome["target"])}
    if kind == "branch":
        condition = z3.is_true(
            model.eval(outcome["condition"], model_completion=True)
        )
        return {
            "kind": kind,
            "condition": condition,
            "taken": int(outcome["taken"]),
            "fallthrough": int(outcome["fallthrough"]),
            "selected": "taken" if condition else "fallthrough",
        }
    if kind == "call":
        return {
            "kind": kind,
            "target": int(outcome["target"]),
            "continuation": int(outcome["continuation"]),
        }
    if kind == "returned":
        return {
            "kind": kind,
            "target": _model_word(model, outcome["target"]),
            "resolved_region_index": next_region_index,
        }
    raise AssertionError(f"unexpected reachable outcome {kind}")


def _model_memory_words(
    model: Any, memory: Any, read_addresses: tuple[Any, ...]
) -> tuple[tuple[int, int], ...]:
    addresses = sorted({_model_word(model, address) for address in read_addresses})
    words = []
    for address in addresses:
        value = 0
        for offset in range(4):
            byte = model.eval(
                z3.Select(memory, z3.BitVecVal((address + offset) & 0xFFFFFFFF, 32)),
                model_completion=True,
            ).as_long()
            value |= (byte & 0xFF) << (offset * 8)
        words.append((address, value))
    return tuple(words)


def _model_word(model: Any, value: Any) -> int:
    evaluated = model.eval(value, model_completion=True)
    if not z3.is_bv_value(evaluated):
        raise _UnsupportedViolationFragment(
            "nonconcrete_solver_value",
            "the proposed mismatch did not reduce to a concrete 32-bit word",
        )
    return int(evaluated.as_long()) & 0xFFFFFFFF


def _semantic_location(
    *,
    semantic_id: str,
    region_index: int,
    region: Mapping[str, Any],
    side: str,
    binary: Any,
    path: tuple[str, ...],
) -> "SemanticLocation":
    span = region.get(side)
    if not isinstance(span, Mapping):
        raise _UnsupportedViolationFragment(
            "region_span_missing", f"selected region omits its {side} span"
        )
    rva = span.get("rva_start")
    size = span.get("size")
    if (
        not isinstance(rva, int)
        or isinstance(rva, bool)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
    ):
        raise _UnsupportedViolationFragment(
            "invalid_region_span", f"selected region has an invalid {side} span"
        )
    raw = binary.pe.get_data(rva, size)
    if len(raw) != size:
        raise _UnsupportedViolationFragment(
            "region_bytes_unavailable", f"selected {side} bytes are outside the PE"
        )
    return SemanticLocation(
        semantic_id=semantic_id,
        region_index=region_index,
        rva=rva,
        bytes_hex=raw.hex(),
        path=tuple(_stable_path_identifier(component) for component in path),
    )


def _stable_path_identifier(value: str) -> str:
    """Canonicalize untrusted symbol text used only for diagnostic paths."""

    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-._")
    if not normalized:
        return "unnamed"
    return normalized[:127].rstrip("-._") or "unnamed"


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


@dataclass(frozen=True)
class BinaryBindings:
    original_sha256: str
    candidate_sha256: str
    relation_contract_sha256: str
    decoded_behaviors_sha256: str
    capability_profile: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "BinaryBindings":
        _exact_fields(payload, {
            "original_sha256", "candidate_sha256", "relation_contract_sha256",
            "decoded_behaviors_sha256", "capability_profile",
        }, context)
        return cls(
            original_sha256=_sha256(payload["original_sha256"], f"{context}.original_sha256"),
            candidate_sha256=_sha256(payload["candidate_sha256"], f"{context}.candidate_sha256"),
            relation_contract_sha256=_sha256(
                payload["relation_contract_sha256"],
                f"{context}.relation_contract_sha256",
            ),
            decoded_behaviors_sha256=_sha256(
                payload["decoded_behaviors_sha256"],
                f"{context}.decoded_behaviors_sha256",
            ),
            capability_profile=_identifier(
                payload["capability_profile"], f"{context}.capability_profile"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "relation_contract_sha256": self.relation_contract_sha256,
            "decoded_behaviors_sha256": self.decoded_behaviors_sha256,
            "capability_profile": self.capability_profile,
        }


@dataclass(frozen=True)
class SemanticLocation:
    semantic_id: str
    region_index: int
    rva: int
    bytes_hex: str
    path: tuple[str, ...]

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "SemanticLocation":
        _exact_fields(payload, {"semantic_id", "region_index", "rva", "bytes_hex", "path"}, context)
        bytes_hex = payload["bytes_hex"]
        if not isinstance(bytes_hex, str) or _HEX_BYTES_RE.fullmatch(bytes_hex) is None:
            raise StageAInputError(f"{context}.bytes_hex must be nonempty lowercase bytes")
        return cls(
            semantic_id=_identifier(payload["semantic_id"], f"{context}.semantic_id"),
            region_index=_integer(payload["region_index"], f"{context}.region_index"),
            rva=_integer(payload["rva"], f"{context}.rva"),
            bytes_hex=bytes_hex,
            path=_string_tuple(
                payload["path"], f"{context}.path", identifiers=True, unique=False
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "semantic_id": self.semantic_id,
            "region_index": self.region_index,
            "rva": self.rva,
            "bytes_hex": self.bytes_hex,
            "path": list(self.path),
        }


@dataclass(frozen=True)
class WitnessLocation:
    original: SemanticLocation
    candidate: SemanticLocation

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "WitnessLocation":
        _exact_fields(payload, {"original", "candidate"}, context)
        return cls(
            original=SemanticLocation.parse(
                _object(payload["original"], f"{context}.original"),
                context=f"{context}.original",
            ),
            candidate=SemanticLocation.parse(
                _object(payload["candidate"], f"{context}.candidate"),
                context=f"{context}.candidate",
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "original": self.original.to_payload(),
            "candidate": self.candidate.to_payload(),
        }


@dataclass(frozen=True)
class ConcreteState:
    registers: tuple[tuple[str, int], ...]
    eflags: int
    memory_words: tuple[tuple[int, int], ...]
    path_guards: tuple[str, ...]
    world_state_sha256: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ConcreteState":
        _exact_fields(payload, {
            "registers", "eflags", "memory_words", "path_guards",
            "world_state_sha256",
        }, context)
        raw_registers = _object(payload["registers"], f"{context}.registers")
        expected_registers = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
        _exact_fields(raw_registers, expected_registers, f"{context}.registers")
        registers = tuple(
            (register, _word(raw_registers[register], f"{context}.registers.{register}"))
            for register in sorted(expected_registers)
        )
        raw_memory = payload["memory_words"]
        if not isinstance(raw_memory, list):
            raise StageAInputError(f"{context}.memory_words must be a list")
        memory_words: list[tuple[int, int]] = []
        for index, item in enumerate(raw_memory):
            item_context = f"{context}.memory_words[{index}]"
            row = _object(item, item_context)
            _exact_fields(row, {"address", "value"}, item_context)
            memory_words.append((
                _word(row["address"], f"{item_context}.address"),
                _word(row["value"], f"{item_context}.value"),
            ))
        if len({address for address, _value in memory_words}) != len(memory_words):
            raise StageAInputError(f"{context}.memory_words addresses must be unique")
        return cls(
            registers=registers,
            eflags=_word(payload["eflags"], f"{context}.eflags"),
            memory_words=tuple(memory_words),
            path_guards=_string_tuple(
                payload["path_guards"], f"{context}.path_guards",
                identifiers=True, unique=False
            ),
            world_state_sha256=_sha256(
                payload["world_state_sha256"], f"{context}.world_state_sha256"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "registers": dict(self.registers),
            "eflags": self.eflags,
            "memory_words": [
                {"address": address, "value": value}
                for address, value in self.memory_words
            ],
            "path_guards": list(self.path_guards),
            "world_state_sha256": self.world_state_sha256,
        }


@dataclass(frozen=True)
class ReachabilityStep:
    region_index: int
    rva: int
    bytes_hex: str
    decoded_ir_sha256: str
    selected_outcome: Mapping[str, Any]
    next_region_index: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ReachabilityStep":
        _exact_fields(payload, {
            "region_index", "rva", "bytes_hex", "decoded_ir_sha256",
            "selected_outcome", "next_region_index",
        }, context)
        bytes_hex = payload["bytes_hex"]
        if not isinstance(bytes_hex, str) or _HEX_BYTES_RE.fullmatch(bytes_hex) is None:
            raise StageAInputError(f"{context}.bytes_hex must be nonempty lowercase bytes")
        outcome = _object(payload["selected_outcome"], f"{context}.selected_outcome")
        if outcome.get("kind") not in {"jump", "branch", "call", "returned"}:
            raise StageAInputError(f"{context}.selected_outcome is unsupported")
        return cls(
            region_index=_integer(payload["region_index"], f"{context}.region_index"),
            rva=_integer(payload["rva"], f"{context}.rva"),
            bytes_hex=bytes_hex,
            decoded_ir_sha256=_sha256(
                payload["decoded_ir_sha256"], f"{context}.decoded_ir_sha256"
            ),
            selected_outcome=dict(outcome),
            next_region_index=_integer(
                payload["next_region_index"], f"{context}.next_region_index"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "region_index": self.region_index,
            "rva": self.rva,
            "bytes_hex": self.bytes_hex,
            "decoded_ir_sha256": self.decoded_ir_sha256,
            "selected_outcome": dict(self.selected_outcome),
            "next_region_index": self.next_region_index,
        }


@dataclass(frozen=True)
class ReachabilityWitness:
    launch_profile: str
    root_region_index: int
    target_region_index: int
    original_launch_state: ConcreteState
    candidate_launch_state: ConcreteState
    original_steps: tuple[ReachabilityStep, ...]
    candidate_steps: tuple[ReachabilityStep, ...]

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "ReachabilityWitness":
        _exact_fields(payload, {
            "launch_profile", "root_region_index", "target_region_index",
            "original_launch_state", "candidate_launch_state", "original_steps",
            "candidate_steps",
        }, context)
        def steps(field: str) -> tuple[ReachabilityStep, ...]:
            raw = payload[field]
            if not isinstance(raw, list):
                raise StageAInputError(f"{context}.{field} must be a list")
            return tuple(
                ReachabilityStep.parse(
                    _object(row, f"{context}.{field}[{index}]"),
                    context=f"{context}.{field}[{index}]",
                )
                for index, row in enumerate(raw)
            )
        result = cls(
            launch_profile=_identifier(
                payload["launch_profile"], f"{context}.launch_profile"
            ),
            root_region_index=_integer(
                payload["root_region_index"], f"{context}.root_region_index"
            ),
            target_region_index=_integer(
                payload["target_region_index"], f"{context}.target_region_index"
            ),
            original_launch_state=ConcreteState.parse(
                _object(payload["original_launch_state"], f"{context}.original_launch_state"),
                context=f"{context}.original_launch_state",
            ),
            candidate_launch_state=ConcreteState.parse(
                _object(payload["candidate_launch_state"], f"{context}.candidate_launch_state"),
                context=f"{context}.candidate_launch_state",
            ),
            original_steps=steps("original_steps"),
            candidate_steps=steps("candidate_steps"),
        )
        if len(result.original_steps) != len(result.candidate_steps):
            raise StageAInputError(f"{context} paths must have equal step counts")
        return result

    def to_payload(self) -> dict[str, Any]:
        return {
            "launch_profile": self.launch_profile,
            "root_region_index": self.root_region_index,
            "target_region_index": self.target_region_index,
            "original_launch_state": self.original_launch_state.to_payload(),
            "candidate_launch_state": self.candidate_launch_state.to_payload(),
            "original_steps": [step.to_payload() for step in self.original_steps],
            "candidate_steps": [step.to_payload() for step in self.candidate_steps],
        }


@dataclass(frozen=True)
class MismatchEffect:
    kind: str
    location: str
    value: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "MismatchEffect":
        _exact_fields(payload, {"kind", "location", "value"}, context)
        kind = payload["kind"]
        if kind not in {"word", "boolean", "control_target", "event_identity"}:
            raise StageAInputError(f"{context}.kind is unsupported")
        return cls(
            kind=str(kind),
            location=_nonempty_string(payload["location"], f"{context}.location"),
            value=_word(payload["value"], f"{context}.value"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "location": self.location, "value": self.value}


@dataclass(frozen=True)
class Mismatch:
    kind: str
    relation_atom: str
    original_effect: MismatchEffect
    candidate_effect: MismatchEffect
    observation: str
    event_index: int | None

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "Mismatch":
        _exact_fields(payload, {
            "kind", "relation_atom", "original_effect", "candidate_effect",
            "observation", "event_index",
        }, context)
        kind = payload["kind"]
        if kind not in _MISMATCH_KINDS:
            raise StageAInputError(f"{context}.kind is unsupported")
        event_index_raw = payload["event_index"]
        event_index = (
            None
            if event_index_raw is None
            else _integer(event_index_raw, f"{context}.event_index")
        )
        if (kind == "external_event") != (event_index is not None):
            raise StageAInputError(
                f"{context}.event_index is required exactly for external-event mismatches"
            )
        return cls(
            kind=str(kind),
            relation_atom=_identifier(payload["relation_atom"], f"{context}.relation_atom"),
            original_effect=MismatchEffect.parse(
                _object(payload["original_effect"], f"{context}.original_effect"),
                context=f"{context}.original_effect",
            ),
            candidate_effect=MismatchEffect.parse(
                _object(payload["candidate_effect"], f"{context}.candidate_effect"),
                context=f"{context}.candidate_effect",
            ),
            observation=_identifier(payload["observation"], f"{context}.observation"),
            event_index=event_index,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "relation_atom": self.relation_atom,
            "original_effect": self.original_effect.to_payload(),
            "candidate_effect": self.candidate_effect.to_payload(),
            "observation": self.observation,
            "event_index": self.event_index,
        }


@dataclass(frozen=True)
class ViolationWitness:
    id: str
    obligation_id: str
    family: str
    bindings: BinaryBindings
    location: WitnessLocation
    reachability: ReachabilityWitness
    original_pre_state: ConcreteState
    candidate_pre_state: ConcreteState
    mismatch: Mismatch
    replay: tuple[str, ...]
    format: str = VIOLATION_WITNESS_FORMAT

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ViolationWitness":
        context = "Stage A violation witness"
        _exact_fields(payload, {
            "format", "id", "obligation_id", "family", "bindings", "location",
            "reachability", "original_pre_state", "candidate_pre_state", "mismatch",
            "replay",
        }, context)
        if payload["format"] != VIOLATION_WITNESS_FORMAT:
            raise StageAInputError("unsupported Stage A violation witness format")
        replay = _string_tuple(
            payload["replay"], f"{context}.replay", unique=False
        )
        if not replay:
            raise StageAInputError("Stage A violation replay command must not be empty")
        witness = cls(
            id=_identifier(payload["id"], f"{context}.id"),
            obligation_id=_nonempty_string(
                payload["obligation_id"], f"{context}.obligation_id"
            ),
            family=_identifier(payload["family"], f"{context}.family"),
            bindings=BinaryBindings.parse(
                _object(payload["bindings"], f"{context}.bindings"),
                context=f"{context}.bindings",
            ),
            location=WitnessLocation.parse(
                _object(payload["location"], f"{context}.location"),
                context=f"{context}.location",
            ),
            reachability=ReachabilityWitness.parse(
                _object(payload["reachability"], f"{context}.reachability"),
                context=f"{context}.reachability",
            ),
            original_pre_state=ConcreteState.parse(
                _object(payload["original_pre_state"], f"{context}.original_pre_state"),
                context=f"{context}.original_pre_state",
            ),
            candidate_pre_state=ConcreteState.parse(
                _object(payload["candidate_pre_state"], f"{context}.candidate_pre_state"),
                context=f"{context}.candidate_pre_state",
            ),
            mismatch=Mismatch.parse(
                _object(payload["mismatch"], f"{context}.mismatch"),
                context=f"{context}.mismatch",
            ),
            replay=replay,
        )
        if witness.mismatch.original_effect.value == witness.mismatch.candidate_effect.value:
            raise StageAInputError("violation witness effects do not conflict")
        return witness

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "id": self.id,
            "obligation_id": self.obligation_id,
            "family": self.family,
            "bindings": self.bindings.to_payload(),
            "location": self.location.to_payload(),
            "reachability": self.reachability.to_payload(),
            "original_pre_state": self.original_pre_state.to_payload(),
            "candidate_pre_state": self.candidate_pre_state.to_payload(),
            "mismatch": self.mismatch.to_payload(),
            "replay": list(self.replay),
        }


def _validate_witness_input_bindings(
    *,
    witness: ViolationWitness,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
) -> None:
    normalized_relation_path = Path(prepared) / "relation-contract.json"
    decoded_path = Path(prepared) / "relational-decoded-behaviors.json"
    if not normalized_relation_path.is_file():
        raise StageAInputError(
            "violation replay requires the normalized relation contract"
        )
    if not decoded_path.is_file():
        raise StageAInputError("violation replay requires bound decoded behaviors")
    expected = {
        "original": case.artifact("original_pe").sha256,
        "candidate": case.artifact("candidate_pe").sha256,
        "relation": sha256_file(normalized_relation_path),
        "decoded": sha256_file(decoded_path),
    }
    observed = {
        "original": witness.bindings.original_sha256,
        "candidate": witness.bindings.candidate_sha256,
        "relation": witness.bindings.relation_contract_sha256,
        "decoded": witness.bindings.decoded_behaviors_sha256,
    }
    if observed != expected:
        raise StageAInputError("violation witness input bindings are stale")
    if witness.bindings.capability_profile != case.capability_profile:
        raise StageAInputError("violation witness capability profile does not match")
    if case.mutation is None:
        raise StageAInputError("violation witness requires a declared negative mutation")
    if (
        witness.location.original.semantic_id != case.mutation.location_id
        or witness.location.candidate.semantic_id != case.mutation.location_id
    ):
        raise StageAInputError("violation witness semantic location does not match mutation")
    if not _location_bytes_match(
        case.artifact("original_pe").verify(case_root), witness.location.original
    ):
        raise StageAInputError("violation witness original bytes do not match the PE")
    if not _location_bytes_match(
        case.artifact("candidate_pe").verify(case_root), witness.location.candidate
    ):
        raise StageAInputError("violation witness candidate bytes do not match the PE")
    _validate_reachability_bindings(
        witness=witness,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )


def _validate_reachability_bindings(
    *, witness: ViolationWitness, case: CaseManifest, case_root: Path, prepared: Path,
) -> None:
    reachability = witness.reachability
    if reachability.launch_profile != "pe32-console-launch-v1":
        raise StageAInputError("violation reachability uses an unsupported launch profile")
    if reachability.target_region_index != witness.location.original.region_index:
        raise StageAInputError("violation reachability does not end at the mismatch region")
    contract = _load_object(Path(prepared) / "relation-contract.json", "relation contract")
    decoded = _load_object(
        Path(prepared) / "relational-decoded-behaviors.json", "decoded behaviors"
    )
    regions = contract.get("regions")
    decoded_regions = decoded.get("regions")
    if not isinstance(regions, list) or not isinstance(decoded_regions, list):
        raise StageAInputError("violation reachability requires prepared regions")
    if not 0 <= reachability.root_region_index < len(regions):
        raise StageAInputError("violation reachability root is outside the contract")
    root = regions[reachability.root_region_index]
    if not isinstance(root, Mapping) or root.get("root") is not True:
        raise StageAInputError("violation reachability must start at a checked root")
    original_path = case.artifact("original_pe").verify(case_root)
    candidate_path = case.artifact("candidate_pe").verify(case_root)
    for side, steps, binary_path in (
        ("original", reachability.original_steps, original_path),
        ("candidate", reachability.candidate_steps, candidate_path),
    ):
        expected_region = reachability.root_region_index
        for index, step in enumerate(steps):
            if step.region_index != expected_region:
                raise StageAInputError(
                    f"violation {side} reachability path is discontinuous at step {index}"
                )
            if not 0 <= step.region_index < len(regions):
                raise StageAInputError(f"violation {side} path region is outside contract")
            region = regions[step.region_index]
            decoded_region = decoded_regions[step.region_index]
            if not isinstance(region, Mapping) or not isinstance(decoded_region, Mapping):
                raise StageAInputError(f"violation {side} path region is malformed")
            span = region.get(side)
            ir = decoded_region.get(f"{side}_ir")
            if not isinstance(span, Mapping) or not isinstance(ir, Mapping):
                raise StageAInputError(f"violation {side} path span or IR is missing")
            if (
                step.rva != span.get("rva_start")
                or len(bytes.fromhex(step.bytes_hex)) != span.get("size")
                or step.decoded_ir_sha256 != _canonical_sha256(ir)
            ):
                raise StageAInputError(f"violation {side} path binding is stale")
            location = SemanticLocation(
                semantic_id=f"path-step-{index}",
                region_index=step.region_index,
                rva=step.rva,
                bytes_hex=step.bytes_hex,
                path=("reachability", side),
            )
            if not _location_bytes_match(binary_path, location):
                raise StageAInputError(f"violation {side} path bytes do not match the PE")
            expected_region = step.next_region_index
        if expected_region != reachability.target_region_index:
            raise StageAInputError(
                f"violation {side} reachability path does not reach its target"
            )


def validate_checked_violation(
    *,
    witness_path: Path,
    audit_path: Path,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
    flake: Path | None = None,
    builders_file: Path | None = None,
) -> dict[str, Any]:
    witness_path = Path(witness_path)
    audit_path = Path(audit_path)
    witness = ViolationWitness.parse(_load_object(witness_path, "violation witness"))
    _validate_witness_input_bindings(
        witness=witness,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )
    audit, audit_provenance = _kernel_authoritative_audit(
        witness_path=witness_path,
        audit_path=audit_path,
        case=case,
        case_root=case_root,
        prepared=prepared,
        flake=flake,
        builders_file=builders_file,
    )
    return _validate_checked_violation_audit(
        witness=witness,
        witness_path=witness_path,
        audit=audit,
        audit_provenance=audit_provenance,
        case=case,
        case_root=case_root,
        prepared=prepared,
    )


def _validate_checked_violation_audit(
    *,
    witness: "ViolationWitness",
    witness_path: Path,
    audit: Mapping[str, Any],
    audit_provenance: str,
    case: CaseManifest,
    case_root: Path,
    prepared: Path,
) -> dict[str, Any]:
    """Validate one kernel-owned audit without replaying its proof a second time."""

    required_audit_fields = {
        "format", "status", "witness_sha256", "theorem", "lean_trust",
        "observed_axioms", "unexpected_axioms", "decoded_behaviors_sha256",
        "original_sha256", "candidate_sha256", "reachability_sha256",
        "proof_source_sha256", "mismatch_theorem", "mismatch_kind",
    }
    optional_audit_fields: set[str] = set()
    missing_audit_fields = sorted(required_audit_fields - set(audit))
    unexpected_audit_fields = sorted(
        set(audit) - required_audit_fields - optional_audit_fields
    )
    if missing_audit_fields or unexpected_audit_fields:
        details = []
        if missing_audit_fields:
            details.append(f"missing fields {missing_audit_fields}")
        if unexpected_audit_fields:
            details.append(f"unexpected fields {unexpected_audit_fields}")
        raise StageAInputError(
            "violation Lean audit has " + " and ".join(details)
        )
    if audit["format"] != VIOLATION_CHECK_FORMAT:
        raise StageAInputError("unsupported violation Lean audit format")
    expected_original = case.artifact("original_pe").sha256
    expected_candidate = case.artifact("candidate_pe").sha256
    normalized_relation_path = Path(prepared) / "relation-contract.json"
    expected_relation = sha256_file(normalized_relation_path)
    decoded_path = Path(prepared) / "relational-decoded-behaviors.json"
    checks = {
        "audit_checked": audit["status"] == "checked",
        "witness_hash_matches": audit["witness_sha256"] == sha256_file(witness_path),
        "lean_trust_zero": audit["lean_trust"] == 0,
        "theorem_is_violation_witness": (
            audit["theorem"] == (
                "StageA.GeneratedRelationalCounterexample."
                "reachableExactCounterexample"
            )
        ),
        "reachability_binding": audit["reachability_sha256"] == _canonical_sha256(
            witness.reachability.to_payload()
        ),
        "classified_mismatch_checked": (
            audit.get("mismatch_theorem")
            == (
                "StageA.GeneratedRelationalCounterexample."
                "reachableClassifiedMismatchChecked"
            )
            and audit.get("mismatch_kind") == witness.mismatch.kind
        ),
        "axioms_approved": (
            isinstance(audit["observed_axioms"], list)
            and set(audit["observed_axioms"]).issubset(RELATIONAL_APPROVED_AXIOMS)
            and audit["unexpected_axioms"] == []
        ),
        "original_binding": (
            witness.bindings.original_sha256 == expected_original
            and audit["original_sha256"] == expected_original
        ),
        "candidate_binding": (
            witness.bindings.candidate_sha256 == expected_candidate
            and audit["candidate_sha256"] == expected_candidate
        ),
        "relation_binding": witness.bindings.relation_contract_sha256 == expected_relation,
        "decoded_binding": (
            witness.bindings.decoded_behaviors_sha256 == sha256_file(decoded_path)
            and audit["decoded_behaviors_sha256"] == sha256_file(decoded_path)
        ),
        "expected_family": case.expectation.witness_family == witness.family,
        "original_bytes_match": _location_bytes_match(
            case.artifact("original_pe").verify(case_root), witness.location.original
        ),
        "candidate_bytes_match": _location_bytes_match(
            case.artifact("candidate_pe").verify(case_root), witness.location.candidate
        ),
    }
    status = "violated" if all(checks.values()) else "incomplete"
    return {
        "format": "stage-a-checked-violation-result-v1",
        "status": status,
        "violation_id": witness.id,
        "obligation_id": witness.obligation_id,
        "family": witness.family,
        "checks": checks,
        "first_proved_mismatch": {
            "original": witness.location.original.to_payload(),
            "candidate": witness.location.candidate.to_payload(),
            "relation_atom": witness.mismatch.relation_atom,
            "original_effect": witness.mismatch.original_effect.to_payload(),
            "candidate_effect": witness.mismatch.candidate_effect.to_payload(),
        },
        "trust": {
            "role": "checked_inequivalence_witness",
            "can_authorize_pass": False,
            "raw_solver_status_sufficient": False,
            "audit_provenance": audit_provenance,
        },
    }


def _kernel_authoritative_audit(
    *, witness_path: Path, audit_path: Path, case: CaseManifest,
    case_root: Path, prepared: Path, flake: Path | None,
    builders_file: Path | None,
) -> tuple[Mapping[str, Any], str]:
    key = str(audit_path.resolve())
    fresh = _FRESH_KERNEL_REPLAYS.get(key)
    if (
        fresh is not None
        and audit_path.is_file()
        and fresh == (sha256_file(audit_path), sha256_file(witness_path))
    ):
        return _load_object(audit_path, "violation Lean audit"), "fresh-kernel-replay"

    # Persisted writable JSON is never a cache hit for proof authority.  Replay
    # the exact witness through the kernel; Nix integration may keep this cheap
    # by invoking validation inside the derivation that owns the compiled graph.
    with tempfile.TemporaryDirectory(prefix="stage-a-violation-replay-") as temporary:
        replay = produce_checked_violation(
            witness_path=witness_path,
            case=case,
            case_root=case_root,
            prepared=prepared,
            out=Path(temporary) / "checked",
            flake=flake,
            builders_file=builders_file,
        )
        replay_audit = replay.get("audit")
        if replay.get("status") != "checked" or not isinstance(replay_audit, str):
            return {
                "format": VIOLATION_CHECK_FORMAT,
                "status": "incomplete",
                "witness_sha256": sha256_file(witness_path),
                "theorem": "",
                "mismatch_theorem": "",
                "mismatch_kind": "",
                "lean_trust": 1,
                "observed_axioms": [],
                "unexpected_axioms": ["kernel-replay-failed"],
                "decoded_behaviors_sha256": "0" * 64,
                "original_sha256": "0" * 64,
                "candidate_sha256": "0" * 64,
                "reachability_sha256": "0" * 64,
                "proof_source_sha256": "0" * 64,
            }, "kernel-replay-failed"
        return _load_object(Path(replay_audit), "replayed violation Lean audit"), (
            "kernel-replayed-writable-cache"
        )


def _location_bytes_match(binary_path: Path, location: SemanticLocation) -> bool:
    binary = _parse_stage_a_pe(binary_path)
    expected = bytes.fromhex(location.bytes_hex)
    return binary.pe.get_data(location.rva, len(expected)) == expected


def _word(value: Any, context: str) -> int:
    result = _integer(value, context)
    if result >= 2**32:
        raise StageAInputError(f"{context} must be a 32-bit word")
    return result


def _load_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc
    return _object(payload, context)
