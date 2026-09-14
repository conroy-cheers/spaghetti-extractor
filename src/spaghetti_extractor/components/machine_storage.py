"""Shared IA-32 scalar storage addresses for adapters and proof projections."""
from __future__ import annotations

from typing import Mapping

from ..boundary._canonical import BoundaryModelError
from .machine_binding import MachineProjectionV1


def scalar_storage_address(value: object, *, state: str, image_base: str,
                           phase: str | None = None) -> tuple[str, int]:
    projection = MachineProjectionV1.parse(value).payload
    width = projection.get("width")
    observed = projection.get("at")
    if width not in {8, 16, 32} or observed not in {"entry", "exit"} or (
            phase is not None and observed != phase):
        raise BoundaryModelError("scalar storage has an unsupported width or observation phase")
    if projection["kind"] == "static_slot":
        return f"{image_base} + UINT32_C({projection['rva']})", int(width)
    if projection["kind"] != "memory":
        raise BoundaryModelError("scalar storage requires a static slot or addressed memory")
    if projection["access"] != "read_write":
        raise BoundaryModelError("scalar state memory requires read_write access")
    return register_relative_address(projection["address"], state=state, phase=str(observed)), int(width)


def register_relative_address(value: object, *, state: str, phase: str | None = None) -> str:
    """Render an admitted register address, without reading its pointed-to value."""
    register, offset = _register_relative_parts(value, phase=phase)
    # IA-32 effective-address addition wraps at 32 bits on both compiler hosts.
    return f"(uint32_t)({state}.{register} + UINT32_C({offset & 0xffffffff}))"


def reconstruct_register_address(value: object, *, state: str, address: str,
                                 phase: str = "entry") -> str:
    """Restore the base register so the admitted projection yields this address."""
    register, offset = _register_relative_parts(value, phase=phase)
    return f"{state}.{register} = (uint32_t)((uint32_t)({address}) - UINT32_C({offset & 0xffffffff}));"


def _register_relative_parts(value: object, *, phase: str | None) -> tuple[str, int]:
    address = MachineProjectionV1.parse(value).payload
    observed = address.get("at")
    if observed not in {"entry", "exit"} or (phase is not None and observed != phase):
        raise BoundaryModelError("register address has an unsupported observation phase")
    offset = 0
    if address["kind"] == "offset":
        offset = address["offset_bytes"]
        if not -(1 << 31) <= offset < (1 << 31):
            raise BoundaryModelError("register address has an unsupported displacement")
        address = address["base"]
    if (not isinstance(address, Mapping) or address["kind"] != "register"
            or address["width"] != 32 or address["at"] != observed):
        raise BoundaryModelError("address requires a same-phase IA-32 register")
    return str(address["register"]), offset
