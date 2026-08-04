"""Canonical untrusted cutpoints for exact symbolic machine execution.

These boundaries do not prove instruction semantics. They ensure that every
consumer presents the reviewed Lean decoder with a span ending at instructions
whose formal execution yields a continuation-bearing stop outcome.
"""

from __future__ import annotations

from typing import Any

import capstone

from ..stage_binary import StageABinary, StageAInputError
from .x87_profile import instruction_is_x87


_RESTARTABLE_STRING_PREFIXES = frozenset(
    {
        b"\xf3\xa4",  # REP MOVSB
        b"\xf3\xa5",  # REP MOVSD
        b"\xf3\x66\xa5",  # REP MOVSW
        b"\x66\xf3\xa5",
        b"\xf3\xaa",  # REP STOSB
        b"\xf3\xab",  # REP STOSD
        b"\xf3\x66\xab",  # REP STOSW
        b"\x66\xf3\xab",
        b"\xf2\xae",  # REPNE SCASB
        b"\xf3\xae",  # REPE SCASB
        b"\xf2\xaf",  # REPNE SCASD
        b"\xf3\xaf",  # REPE SCASD
        b"\xf2\x66\xaf",  # REPNE SCASW
        b"\x66\xf2\xaf",
        b"\xf3\x66\xaf",  # REPE SCASW
        b"\x66\xf3\xaf",
    }
)


def _instruction_is_restartable_string(instruction: Any) -> bool:
    return bytes(instruction.bytes) in _RESTARTABLE_STRING_PREFIXES


def _instruction_is_semantic_stop(instruction: Any) -> bool:
    return (
        _instruction_is_restartable_string(instruction)
        or instruction.mnemonic
        in {
            "movsd",
            "stosd",
            "div",
            "idiv",
            "lock cmpxchg",
        }
    )


def decode_semantic_cutpoint_span(
    binary: StageABinary,
    span: dict[str, int],
    block_id: str,
    *,
    detail: bool = False,
) -> list[Any]:
    data = binary.pe.get_data(span["rva_start"], span["size"])
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    disassembler.detail = detail
    decoded = list(
        disassembler.disasm(data, binary.image_base + span["rva_start"])
    )
    if not decoded or sum(int(instruction.size) for instruction in decoded) != len(data):
        raise StageAInputError(
            f"mapping block {block_id} does not decode exactly for semantic "
            "cutpoint projection"
        )
    return decoded


def semantic_cutpoint_spans_for_side(
    binary: StageABinary,
    span: dict[str, int],
    block_id: str,
    *,
    periodic: bool = True,
) -> list[dict[str, int]]:
    decoded = decode_semantic_cutpoint_span(binary, span, block_id)
    boundaries = [0]
    for instruction_index, instruction in enumerate(decoded, start=1):
        instruction_start = int(
            instruction.address - binary.image_base - span["rva_start"]
        )
        instruction_stop = instruction_start + int(instruction.size)
        if instruction_is_x87(instruction):
            if instruction_start > boundaries[-1]:
                boundaries.append(instruction_start)
            if instruction_stop < span["size"]:
                boundaries.append(instruction_stop)
            continue
        semantic_stop = _instruction_is_semantic_stop(instruction)
        if (
            _instruction_is_restartable_string(instruction)
            and instruction_start > boundaries[-1]
        ):
            boundaries.append(instruction_start)
        if semantic_stop or (periodic and instruction_index % 4 == 0):
            if instruction_stop < span["size"] and instruction_stop != boundaries[-1]:
                boundaries.append(instruction_stop)
    boundaries.append(span["size"])
    return [
        {
            "rva_start": span["rva_start"] + boundaries[index],
            "rva_end": span["rva_start"] + boundaries[index + 1],
            "size": boundaries[index + 1] - boundaries[index],
        }
        for index in range(len(boundaries) - 1)
    ]


def paired_semantic_cutpoint_spans(
    original: StageABinary,
    candidate: StageABinary,
    original_span: dict[str, int],
    candidate_span: dict[str, int],
    block_id: str,
) -> list[tuple[dict[str, int], dict[str, int]]]:
    periodic = len(
        decode_semantic_cutpoint_span(original, original_span, block_id)
    ) == len(
        decode_semantic_cutpoint_span(candidate, candidate_span, block_id)
    )
    original_spans = semantic_cutpoint_spans_for_side(
        original,
        original_span,
        block_id,
        periodic=periodic,
    )
    candidate_spans = semantic_cutpoint_spans_for_side(
        candidate,
        candidate_span,
        block_id,
        periodic=periodic,
    )
    original_boundaries = [original_spans[0]["rva_start"]] + [
        span["rva_end"] for span in original_spans
    ]
    candidate_boundaries = [candidate_spans[0]["rva_start"]] + [
        span["rva_end"] for span in candidate_spans
    ]
    if len(original_boundaries) != len(candidate_boundaries):
        raise StageAInputError(
            f"mapping block {block_id} has mismatched semantic cutpoint counts: "
            f"original={len(original_boundaries) - 2}, "
            f"candidate={len(candidate_boundaries) - 2}"
        )
    return list(zip(original_spans, candidate_spans, strict=True))
