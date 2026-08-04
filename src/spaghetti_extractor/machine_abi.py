"""Stable machine-level ABI definitions shared by proof and reconstruction paths."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


MACHINE_CALL_ABI_REGISTERS = frozenset({
    "eax", "ebp", "ebx", "ecx", "edi", "edx", "esi",
})
MACHINE_CALL_ABI_TEMPLATES: Mapping[str, Mapping[str, Any]] = {
    "pe32-cdecl-v1": {
        "callee_cleanup": False,
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "clobbered_registers": ["eax", "ecx", "edx"],
    },
    "pe32-stdcall-v1": {
        "callee_cleanup": True,
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "clobbered_registers": ["eax", "ecx", "edx"],
    },
}


@dataclass(frozen=True)
class MachineCallABI:
    template: str
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    callee_cleanup: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "template": self.template,
            "preserved_registers": list(self.preserved_registers),
            "clobbered_registers": list(self.clobbered_registers),
            "callee_cleanup": self.callee_cleanup,
        }


def resolve_machine_call_abi(template: Any) -> MachineCallABI | None:
    if not isinstance(template, str):
        return None
    raw = MACHINE_CALL_ABI_TEMPLATES.get(template)
    if raw is None:
        return None
    preserved = tuple(sorted(str(value) for value in raw["preserved_registers"]))
    clobbered = tuple(sorted(str(value) for value in raw["clobbered_registers"]))
    if (
        set(preserved) | set(clobbered) != set(MACHINE_CALL_ABI_REGISTERS)
        or set(preserved) & set(clobbered)
    ):
        raise ValueError(f"machine ABI template {template!r} is not a partition")
    return MachineCallABI(
        template=template,
        preserved_registers=preserved,
        clobbered_registers=clobbered,
        callee_cleanup=bool(raw["callee_cleanup"]),
    )


__all__ = [
    "MACHINE_CALL_ABI_REGISTERS",
    "MACHINE_CALL_ABI_TEMPLATES",
    "MachineCallABI",
    "resolve_machine_call_abi",
]
