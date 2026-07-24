"""Recover bounded value origins for writes to writable PE32 words.

The analysis is proposal-only. It follows exact decoded predecessor paths and
recognizes only canonical internal code constants and resolver results bound to
generated callable contracts. Joins preserve finite alternatives; an unknown
producer, unsupported call boundary, or unresolved nullable result fails
closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_REG

from .callable_external_proposal import CallableResolverRouteEvidence
from .interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    OriginalCallableExternalRouteBinding,
    OriginalRegion,
)


_REGISTER_NAMES = frozenset(
    ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
)
_Requirement = Literal["any", "zero", "nonzero"]


class FiniteStaticWordProvenanceError(ValueError):
    """A reachable slot write has no complete finite origin proof proposal."""


@dataclass(frozen=True)
class StaticWordWriteOriginEvidence:
    source_target_id: int
    source_rva: int
    instruction_rva: int
    internal_target_ids: tuple[int, ...]
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...]
    value_register: str | None = None
    tail_instruction_rva: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "external_routes": [
                {
                    "abi_contract_id": route.abi_contract_id,
                    "capability_id": route.capability_id,
                    "resolver_contract_id": route.resolver_contract_id,
                    "resource_id": route.resource_id,
                }
                for route in self.external_routes
            ],
            "instruction_rva": self.instruction_rva,
            "internal_target_ids": list(self.internal_target_ids),
            "source_rva": self.source_rva,
            "source_target_id": self.source_target_id,
            "tail_instruction_rva": self.tail_instruction_rva,
            "value_register": self.value_register,
        }


@dataclass(frozen=True)
class FiniteStaticWordOriginEvidence:
    slot_rva: int
    internal_target_ids: tuple[int, ...]
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...]
    writes: tuple[StaticWordWriteOriginEvidence, ...]


@dataclass(frozen=True)
class _Origins:
    internal_target_ids: tuple[int, ...] = ()
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...] = ()

    def merged(self, other: "_Origins") -> "_Origins":
        return _Origins(
            internal_target_ids=tuple(
                dict.fromkeys(
                    (*self.internal_target_ids, *other.internal_target_ids)
                )
            ),
            external_routes=tuple(
                dict.fromkeys((*self.external_routes, *other.external_routes))
            ),
        )


def discover_finite_static_word_origins(
    *,
    pe: pefile.PE,
    image_base: int,
    rows: Mapping[int, Mapping[str, Any]],
    plan: InterpreterMixedOriginalPlan,
    slot_rva: int,
    slot_va: int,
    initial_target_id: int,
    resolver_routes_by_instruction_rva: Mapping[
        int, CallableResolverRouteEvidence
    ],
    alternative_budget: int = 16,
) -> FiniteStaticWordOriginEvidence:
    """Recover every exact reachable write to one static word."""

    if alternative_budget <= 0:
        raise FiniteStaticWordProvenanceError(
            "finite-origin alternative budget must be positive"
        )
    targets_by_rva = {region.rva: region.target_id for region in plan.regions}
    predecessors: dict[int, list[OriginalRegion]] = {}
    reachable = set(plan.reachable_target_ids)
    for region in plan.regions:
        if region.target_id not in reachable:
            continue
        for successor_id in region.successor_ids:
            if successor_id in reachable:
                predecessors.setdefault(successor_id, []).append(region)

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded: dict[int, tuple[Any, ...]] = {}

    def decode(region: OriginalRegion) -> tuple[Any, ...]:
        existing = decoded.get(region.target_id)
        if existing is not None:
            return existing
        data = bytes(pe.get_data(region.rva, region.size))
        instructions = tuple(
            decoder.disasm(data, image_base + region.rva)
        )
        if (
            len(data) != region.size
            or not instructions
            or sum(instruction.size for instruction in instructions)
            != region.size
        ):
            raise FiniteStaticWordProvenanceError(
                f"region 0x{region.rva:x} does not decode over its exact span"
            )
        decoded[region.target_id] = instructions
        return instructions

    writes: list[StaticWordWriteOriginEvidence] = []
    aggregate = _Origins(internal_target_ids=(initial_target_id,))
    for region in plan.regions:
        if region.target_id not in reachable:
            continue
        row = rows.get(region.rva)
        if row is None:
            continue
        events = row.get("ordered_events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, Mapping) or event.get("kind") != "write":
                continue
            address = _constant(event.get("address"))
            width = event.get("width")
            if address is None:
                continue
            if not isinstance(width, int) or isinstance(width, bool):
                if address < slot_va + 4 and slot_va < address + 4:
                    raise FiniteStaticWordProvenanceError(
                        f"write in region 0x{region.rva:x} has no exact width"
                    )
                continue
            if not (address < slot_va + 4 and slot_va < address + width):
                continue
            instruction_rva = event.get("instruction_rva")
            if (
                width != 4
                or address != slot_va
                or not isinstance(instruction_rva, int)
                or isinstance(instruction_rva, bool)
            ):
                raise FiniteStaticWordProvenanceError(
                    f"write in region 0x{region.rva:x} partially overlaps "
                    f"slot RVA 0x{slot_rva:x}"
                )
            value = event.get("value")
            constant = _constant(value)
            register: str | None = None
            if constant is not None:
                origins = _constant_origin(
                    constant,
                    image_base=image_base,
                    targets_by_rva=targets_by_rva,
                    requirement="any",
                )
            else:
                register = _register(value)
                if register is None:
                    raise FiniteStaticWordProvenanceError(
                        f"slot write at 0x{instruction_rva:x} has an "
                        "unsupported value expression"
                    )
                origins = _origins_before(
                    region=region,
                    stop_rva=instruction_rva,
                    register=register,
                    requirement="any",
                    image_base=image_base,
                    targets_by_rva=targets_by_rva,
                    predecessors=predecessors,
                    rows=rows,
                    decode=decode,
                    resolver_routes_by_instruction_rva=(
                        resolver_routes_by_instruction_rva
                    ),
                    active=frozenset(),
                )
            if not origins.internal_target_ids and not origins.external_routes:
                raise FiniteStaticWordProvenanceError(
                    f"slot write at 0x{instruction_rva:x} has no callable "
                    "or internal code origin"
                )
            aggregate = aggregate.merged(origins)
            if (
                len(aggregate.internal_target_ids)
                + len(aggregate.external_routes)
                > alternative_budget
            ):
                raise FiniteStaticWordProvenanceError(
                    f"slot RVA 0x{slot_rva:x} exceeds the finite-origin "
                    f"budget of {alternative_budget}"
                )
            writes.append(
                StaticWordWriteOriginEvidence(
                    source_target_id=region.target_id,
                    source_rva=region.rva,
                    instruction_rva=instruction_rva,
                    internal_target_ids=origins.internal_target_ids,
                    external_routes=origins.external_routes,
                    value_register=register,
                    tail_instruction_rva=(
                        None
                        if register is None
                        else _tail_jump_through_register(
                            decode(region),
                            image_base=image_base,
                            write_instruction_rva=instruction_rva,
                            register=register,
                        )
                    ),
                )
            )
    return FiniteStaticWordOriginEvidence(
        slot_rva=slot_rva,
        internal_target_ids=aggregate.internal_target_ids,
        external_routes=aggregate.external_routes,
        writes=tuple(writes),
    )


def _origins_before(
    *,
    region: OriginalRegion,
    stop_rva: int,
    register: str,
    requirement: _Requirement,
    image_base: int,
    targets_by_rva: Mapping[int, int],
    predecessors: Mapping[int, list[OriginalRegion]],
    rows: Mapping[int, Mapping[str, Any]],
    decode: Any,
    resolver_routes_by_instruction_rva: Mapping[
        int, CallableResolverRouteEvidence
    ],
    active: frozenset[tuple[int, int, str, _Requirement]],
) -> _Origins:
    key = (region.target_id, stop_rva, register, requirement)
    if key in active:
        raise FiniteStaticWordProvenanceError(
            f"register {register} provenance enters an unresolved cycle at "
            f"RVA 0x{region.rva:x}"
        )
    active = active | {key}
    current_register = register
    for instruction in reversed(
        tuple(
            instruction
            for instruction in decode(region)
            if instruction.address - image_base < stop_rva
        )
    ):
        instruction_rva = instruction.address - image_base
        if instruction.mnemonic in {"call", "lcall"}:
            resolver = resolver_routes_by_instruction_rva.get(instruction_rva)
            if (
                resolver is not None
                and resolver.result_register == current_register
            ):
                if resolver.nullable and requirement == "any":
                    raise FiniteStaticWordProvenanceError(
                        f"nullable resolver result at 0x{instruction_rva:x} "
                        "reaches a slot write without a nonzero guard"
                    )
                if requirement == "zero":
                    return _Origins()
                return _Origins(external_routes=(resolver.route,))
            raise FiniteStaticWordProvenanceError(
                f"register {current_register} provenance crosses an "
                f"uncontracted call at 0x{instruction_rva:x}"
            )
        writer = _register_writer(instruction)
        if writer != current_register:
            continue
        if instruction.mnemonic == "mov" and len(instruction.operands) == 2:
            source = instruction.operands[1]
            if source.type == X86_OP_IMM:
                return _constant_origin(
                    int(source.imm) & 0xFFFFFFFF,
                    image_base=image_base,
                    targets_by_rva=targets_by_rva,
                    requirement=requirement,
                )
            if source.type == X86_OP_REG:
                current_register = instruction.reg_name(source.reg)
                if current_register not in _REGISTER_NAMES:
                    break
                continue
        if (
            instruction.mnemonic in {"xor", "sub"}
            and len(instruction.operands) == 2
            and all(operand.type == X86_OP_REG for operand in instruction.operands)
            and instruction.operands[0].reg == instruction.operands[1].reg
        ):
            return _constant_origin(
                0,
                image_base=image_base,
                targets_by_rva=targets_by_rva,
                requirement=requirement,
            )
        raise FiniteStaticWordProvenanceError(
            f"nearest write to {current_register} at 0x{instruction_rva:x} "
            "has no supported finite origin"
        )

    merged = _Origins()
    feasible = 0
    for predecessor in predecessors.get(region.target_id, []):
        edge_requirement = _edge_requirement(
            rows.get(predecessor.rva), region.rva, current_register
        )
        combined = _combine_requirements(requirement, edge_requirement)
        if combined is None:
            continue
        feasible += 1
        merged = merged.merged(
            _origins_before(
                region=predecessor,
                stop_rva=predecessor.rva + predecessor.size,
                register=current_register,
                requirement=combined,
                image_base=image_base,
                targets_by_rva=targets_by_rva,
                predecessors=predecessors,
                rows=rows,
                decode=decode,
                resolver_routes_by_instruction_rva=(
                    resolver_routes_by_instruction_rva
                ),
                active=active,
            )
        )
    if feasible == 0:
        raise FiniteStaticWordProvenanceError(
            f"register {current_register} at RVA 0x{region.rva:x} has no "
            "complete predecessor provenance"
        )
    return merged


def _register_writer(instruction: Any) -> str | None:
    if not instruction.operands:
        return None
    destination = instruction.operands[0]
    if destination.type != X86_OP_REG:
        return None
    register = instruction.reg_name(destination.reg)
    if register not in _REGISTER_NAMES:
        return None
    try:
        _reads, writes = instruction.regs_access()
    except capstone.CsError as error:
        raise FiniteStaticWordProvenanceError(
            f"instruction at 0x{instruction.address:x} has no register-access "
            "metadata"
        ) from error
    return register if destination.reg in writes else None


def _tail_jump_through_register(
    instructions: tuple[Any, ...],
    *,
    image_base: int,
    write_instruction_rva: int,
    register: str,
) -> int | None:
    terminal = instructions[-1]
    if (
        terminal.mnemonic != "jmp"
        or len(terminal.operands) != 1
        or terminal.operands[0].type != X86_OP_REG
        or terminal.reg_name(terminal.operands[0].reg) != register
    ):
        return None
    for instruction in instructions:
        instruction_rva = instruction.address - image_base
        if not write_instruction_rva < instruction_rva < (
            terminal.address - image_base
        ):
            continue
        try:
            _reads, writes = instruction.regs_access()
        except capstone.CsError as error:
            raise FiniteStaticWordProvenanceError(
                f"instruction at 0x{instruction_rva:x} has no register-access "
                "metadata"
            ) from error
        if register in {
            instruction.reg_name(written)
            for written in writes
        }:
            return None
    return terminal.address - image_base


def _constant_origin(
    value: int,
    *,
    image_base: int,
    targets_by_rva: Mapping[int, int],
    requirement: _Requirement,
) -> _Origins:
    if requirement == "zero" and value != 0:
        return _Origins()
    if requirement == "nonzero" and value == 0:
        return _Origins()
    if value == 0:
        return _Origins()
    rva = value - image_base if value >= image_base else value
    target_id = targets_by_rva.get(rva)
    if target_id is None:
        raise FiniteStaticWordProvenanceError(
            f"word 0x{value:x} is not a canonical internal code target"
        )
    return _Origins(internal_target_ids=(target_id,))


def _edge_requirement(
    row: Mapping[str, Any] | None,
    successor_rva: int,
    register: str,
) -> _Requirement:
    if row is None:
        return "any"
    outcome = row.get("outcome")
    if not isinstance(outcome, Mapping) or outcome.get("kind") != "branch":
        return "any"
    condition = outcome.get("condition")
    if not _zero_test_register(condition, register):
        return "any"
    if outcome.get("true_target_rva") == successor_rva:
        return "zero"
    if outcome.get("false_target_rva") == successor_rva:
        return "nonzero"
    return "any"


def _zero_test_register(value: Any, register: str) -> bool:
    if not isinstance(value, Mapping) or value.get("op") != "eq":
        return False
    args = value.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return False
    for expression, zero in ((args[0], args[1]), (args[1], args[0])):
        if _constant(zero) != 0 or not isinstance(expression, Mapping):
            continue
        inner = expression.get("args")
        if (
            expression.get("op") == "and32"
            and isinstance(inner, list)
            and len(inner) == 2
            and all(_register(item) == register for item in inner)
        ):
            return True
    return False


def _combine_requirements(
    left: _Requirement, right: _Requirement
) -> _Requirement | None:
    if left == "any":
        return right
    if right == "any" or left == right:
        return left
    return None


def _constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    if not isinstance(result, int) or isinstance(result, bool):
        return None
    return result & 0xFFFFFFFF


def _register(value: Any) -> str | None:
    if not isinstance(value, Mapping) or value.get("op") != "reg":
        return None
    register = value.get("name")
    return register if register in _REGISTER_NAMES else None


__all__ = [
    "FiniteStaticWordOriginEvidence",
    "FiniteStaticWordProvenanceError",
    "StaticWordWriteOriginEvidence",
    "discover_finite_static_word_origins",
]
