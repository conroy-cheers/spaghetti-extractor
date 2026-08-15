"""Deterministic component-evidence models for checked external call sites.

These models are evidence automation, not authority.  A model is usable only
after the canonical external-site checker has supplied an exact machine
contract, and only when that contract matches the operation-specific footprint
accepted here.  Unsupported operations fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from ..external.contracts import CheckedExternalSiteContract


class ExternalEvidenceModelError(ValueError):
    """A checked external contract has no supported evidence model."""


@dataclass(frozen=True)
class ExternalCallEvaluation:
    register_values: Mapping[str, int]
    defined_registers: frozenset[str]
    flag_values: Mapping[str, int]
    defined_flags: frozenset[str]


MemoryReader = Callable[[int, int], int]


def evaluate_checked_external_call(
    contract: CheckedExternalSiteContract,
    arguments: Sequence[int],
    entry_state: Mapping[str, int],
    read_memory: MemoryReader,
) -> ExternalCallEvaluation:
    """Evaluate one supported, checked call without executing the reference PE."""

    if (
        contract.transfer_kind != "call"
        or contract.disposition != "returns_here"
        or contract.profile_disposition != "returns"
        or contract.callback_effect != "none"
        or contract.world_effect != "none"
    ):
        raise ExternalEvidenceModelError(
            "external evidence requires an ordinary returning call with no "
            "callback or world transition"
        )
    if len(arguments) != contract.argument_words:
        raise ExternalEvidenceModelError(
            "external evidence argument count disagrees with the checked contract"
        )
    identity = contract.identity
    if identity.kind != "import" or identity.dll is None or identity.symbol is None:
        raise ExternalEvidenceModelError(
            "external evidence currently requires a named imported operation"
        )
    key = (identity.dll.lower(), identity.symbol.lower())
    if key == ("msvcrt.dll", "memcmp"):
        result = _memcmp(contract, arguments, read_memory)
    else:
        raise ExternalEvidenceModelError(
            f"no component evidence model for {identity.dll}!{identity.symbol}"
        )

    preserved = frozenset({"ebx", "esi", "edi", "ebp", "esp"})
    values = {
        register: int(entry_state.get(register, 0)) & 0xFFFFFFFF
        for register in preserved
    }
    values.update({"eax": result & 0xFFFFFFFF, "ecx": 0, "edx": 0})
    return ExternalCallEvaluation(
        register_values=values,
        defined_registers=preserved | {"eax"},
        flag_values={name: 0 for name in ("cf", "zf", "sf", "of", "pf", "df")},
        defined_flags=frozenset(),
    )


def _memcmp(
    contract: CheckedExternalSiteContract,
    arguments: Sequence[int],
    read_memory: MemoryReader,
) -> int:
    expected_footprints = (
        {
            "access": "read",
            "base_argument": 0,
            "offset": 0,
            "size": {"kind": "argument", "argument": 2, "scale": 1},
            "nullable": False,
        },
        {
            "access": "read",
            "base_argument": 1,
            "offset": 0,
            "size": {"kind": "argument", "argument": 2, "scale": 1},
            "nullable": False,
        },
    )
    if (
        contract.abi_template != "pe32-cdecl-v1"
        or contract.argument_words != 3
        or contract.memory_effect != "readOnly"
        or contract.memory_footprints != expected_footprints
        or contract.result_register_relations
        != ({"register": "eax", "relation": "exact"},)
        or contract.out_pointer_relations
        or contract.out_interface_relations
    ):
        raise ExternalEvidenceModelError(
            "memcmp evidence model does not match the checked ABI/effect contract"
        )
    left, right, count = (int(value) & 0xFFFFFFFF for value in arguments)
    if count and (left == 0 or right == 0):
        raise ExternalEvidenceModelError(
            "memcmp received a null pointer for a nonempty range"
        )
    for offset in range(count):
        left_byte = read_memory((left + offset) & 0xFFFFFFFF, 1)
        right_byte = read_memory((right + offset) & 0xFFFFFFFF, 1)
        if left_byte != right_byte:
            return (left_byte - right_byte) & 0xFFFFFFFF
    return 0


__all__ = [
    "ExternalCallEvaluation",
    "ExternalEvidenceModelError",
    "evaluate_checked_external_call",
]
