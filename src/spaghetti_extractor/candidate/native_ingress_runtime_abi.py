"""Single owner for the exact IA-32 native-ingress runtime storage ABI."""

from __future__ import annotations

from typing import Any

from ..errors import ToolkitInputError


THREAD_MAGIC = 0x53505854
THREAD_ABI_VERSION = 2
THREAD_HEADER_BYTES = 128
INGRESS_FRAME_BYTES = 76
MAX_INGRESS_DEPTH = 64
MAX_CAPABILITY_GENERATIONS = 64
FRAME_REGION_OFFSET = THREAD_HEADER_BYTES
FRAME_REGION_BYTES = INGRESS_FRAME_BYTES * MAX_INGRESS_DEPTH
STATE_REGION_OFFSET = 0x2000
MACHINE_STATE_BYTES = 252
STATE_PAIR_BYTES = MACHINE_STATE_BYTES * 2
STATE_REGION_BYTES = STATE_PAIR_BYTES * MAX_INGRESS_DEPTH
DIAGNOSTIC_REGION_OFFSET = 0xA000
DIAGNOSTIC_REGION_BYTES = 0x1000
RUNTIME_THREAD_STATE_OFFSET = 0xB000
RUNTIME_THREAD_STATE_BYTES = 0x10
RUNTIME_CONTEXT_OFFSET = 0xC000
EXCEPTION_CHAIN_SCRATCH_BYTES = 4 * 80
MINIMUM_RUNTIME_CONTROL_BYTES = 0x80000
PRIVATE_STACK_USABLE_BYTES = 0x10000
PRIVATE_STACK_SLICE_BYTES = (
    PRIVATE_STACK_USABLE_BYTES + EXCEPTION_CHAIN_SCRATCH_BYTES
)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def exact_tls_regions(
    *, control_bytes: int, stack_bytes: int
) -> dict[str, dict[str, Any]]:
    """Describe every byte of the checked PE-TLS runtime allocation."""

    if control_bytes < MINIMUM_RUNTIME_CONTROL_BYTES:
        raise ToolkitInputError(
            "runtime TLS control size is below the native ingress ABI"
        )
    stack_offset = align_up(control_bytes, 16)
    return {
        "thread_header": {"offset": 0, "extent": THREAD_HEADER_BYTES},
        "ingress_frames": {
            "offset": FRAME_REGION_OFFSET,
            "extent": FRAME_REGION_BYTES,
            "element_bytes": INGRESS_FRAME_BYTES,
            "capacity": MAX_INGRESS_DEPTH,
        },
        "captured_machine_states": {
            "offset": STATE_REGION_OFFSET,
            "extent": STATE_REGION_BYTES,
            "element_bytes": STATE_PAIR_BYTES,
            "capacity": MAX_INGRESS_DEPTH,
        },
        "diagnostics_and_outcomes": {
            "offset": DIAGNOSTIC_REGION_OFFSET,
            "extent": DIAGNOSTIC_REGION_BYTES,
        },
        "runtime_thread_state": {
            "offset": RUNTIME_THREAD_STATE_OFFSET,
            "extent": RUNTIME_THREAD_STATE_BYTES,
        },
        "runtime_context": {
            "offset": RUNTIME_CONTEXT_OFFSET,
            "extent": control_bytes - RUNTIME_CONTEXT_OFFSET,
        },
        "private_stack": {
            "offset": stack_offset,
            "extent": stack_bytes,
            "growth": "bounded_slices_x86_down",
            "slice_bytes": PRIVATE_STACK_SLICE_BYTES,
            "usable_bytes_per_slice": PRIVATE_STACK_USABLE_BYTES,
            "reserved_top_bytes_per_slice": EXCEPTION_CHAIN_SCRATCH_BYTES,
        },
    }


__all__ = [
    "DIAGNOSTIC_REGION_BYTES",
    "DIAGNOSTIC_REGION_OFFSET",
    "EXCEPTION_CHAIN_SCRATCH_BYTES",
    "FRAME_REGION_BYTES",
    "FRAME_REGION_OFFSET",
    "INGRESS_FRAME_BYTES",
    "MACHINE_STATE_BYTES",
    "MAX_CAPABILITY_GENERATIONS",
    "MAX_INGRESS_DEPTH",
    "MINIMUM_RUNTIME_CONTROL_BYTES",
    "PRIVATE_STACK_SLICE_BYTES",
    "PRIVATE_STACK_USABLE_BYTES",
    "RUNTIME_CONTEXT_OFFSET",
    "RUNTIME_THREAD_STATE_BYTES",
    "RUNTIME_THREAD_STATE_OFFSET",
    "STATE_PAIR_BYTES",
    "STATE_REGION_BYTES",
    "STATE_REGION_OFFSET",
    "THREAD_ABI_VERSION",
    "THREAD_HEADER_BYTES",
    "THREAD_MAGIC",
    "align_up",
    "exact_tls_regions",
]
