"""Bounded rooted IA-32 instruction-view discovery over untrusted bytes.

This module produces proposal data only.  A discovered view is not evidence that
the bytes came from the exact PE or that Capstone's instruction has the required
semantics.  Consumers must check exact PE-byte and semantic bindings downstream
before accepting any view.
"""

from __future__ import annotations

import heapq
import operator
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

import capstone
from capstone import x86_const


ROOTED_INSTRUCTION_VIEW_FORMAT = "rooted-ia32-instruction-views-v1"
_MAX_INSTRUCTION_SIZE = 15
_U32_LIMIT = 1 << 32

_EDGE_ORDER = {
    "branch_taken": 0,
    "branch_fallthrough": 1,
    "jump": 2,
    "call_target": 3,
    "call_continuation": 4,
    "fallthrough": 5,
}

_FAR_CONTROL_IDS = frozenset(
    instruction_id
    for name in (
        "X86_INS_LCALL",
        "X86_INS_LJMP",
        "X86_INS_RETF",
        "X86_INS_RETFQ",
    )
    if (instruction_id := getattr(x86_const, name, None)) is not None
)
_SYSTEM_CONTROL_MNEMONICS = frozenset(
    {
        "hlt",
        "int",
        "int1",
        "int3",
        "into",
        "iret",
        "iretd",
        "iretq",
        "syscall",
        "sysenter",
        "sysexit",
        "sysret",
        "ud2",
    }
)


@dataclass(frozen=True)
class _Successor:
    kind: str
    target_rva: int


@dataclass(frozen=True)
class _View:
    rva_start: int
    rva_end: int
    encoded: bytes
    mnemonic: str
    op_str: str
    control_kind: str
    successors: tuple[_Successor, ...]


@dataclass(frozen=True)
class _Predecessor:
    source_rva: int
    edge_kind: str


@dataclass(frozen=True)
class _Issue:
    code: str
    message: str
    rva: int
    pending_rvas: tuple[int, ...] = ()


def discover_rooted_instruction_views(
    binary: Any,
    seed_rvas: Iterable[int],
    existing_rvas: Iterable[int],
    instruction_budget: int,
) -> dict[str, Any]:
    """Discover a deterministic, bounded instruction-view proposal.

    ``binary`` may be a :class:`StageABinary` or a clean equivalent exposing
    ``bitness``, ``image_base``, executable ``sections``, and one of
    ``read_rva(rva, size)``, ``get_data(rva, size)``, or ``pe.get_data``.
    Existing RVAs are validated when reached, recorded as merge destinations,
    and never decoded.

    The returned mapping is proposal-only.  Exact PE identity, exact byte
    coverage, and instruction semantics remain downstream obligations.
    """

    bitness = _integer_field(binary, "bitness")
    if bitness != 32:
        raise ValueError(
            f"rooted instruction-view discovery requires IA-32, got {bitness}-bit"
        )
    image_base = _integer_field(binary, "image_base")
    if not 0 <= image_base < _U32_LIMIT:
        raise ValueError("binary image_base must be an unsigned 32-bit value")

    budget = _index(instruction_budget, "instruction_budget")
    if budget < 0:
        raise ValueError("instruction_budget must be non-negative")
    seeds = frozenset(_rva_values(seed_rvas, "seed_rvas"))
    existing = frozenset(_rva_values(existing_rvas, "existing_rvas"))
    sections = _sections(binary)
    reader = _reader(binary)

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True

    pending = list(seeds)
    heapq.heapify(pending)
    queued = set(seeds)
    reached: set[int] = set()
    incoming: dict[int, set[_Predecessor]] = {}
    views: dict[int, _View] = {}
    merges: set[int] = set()
    issues: dict[int, _Issue] = {}
    budget_issue: _Issue | None = None

    def enqueue(successor: _Successor, source_rva: int) -> None:
        target = successor.target_rva
        incoming.setdefault(target, set()).add(
            _Predecessor(source_rva, successor.kind)
        )
        if target not in reached and target not in queued:
            heapq.heappush(pending, target)
            queued.add(target)

    while pending:
        rva = heapq.heappop(pending)
        queued.remove(rva)
        if rva in reached:
            continue
        reached.add(rva)

        section_end = _executable_section_end(sections, rva)
        if section_end is None:
            code = (
                "seed_outside_executable_section"
                if rva in seeds
                else "target_outside_executable_section"
            )
            subject = "seed" if rva in seeds else "target"
            issues[rva] = _Issue(
                code,
                f"reached {subject} RVA {_format_rva(rva)} is outside executable sections",
                rva,
            )
            continue

        if rva in existing:
            merges.add(rva)
            continue

        if len(views) >= budget:
            remaining = tuple(sorted({rva, *pending}))
            budget_issue = _Issue(
                "instruction_budget_exhausted",
                f"instruction budget {budget} was exhausted before {_format_rva(rva)}",
                rva,
                remaining,
            )
            break

        instruction = _decode_one(
            decoder,
            reader,
            image_base=image_base,
            rva=rva,
            section_end=section_end,
        )
        if instruction is None:
            issues[rva] = _Issue(
                "undecodable_instruction",
                f"no IA-32 instruction decodes at RVA {_format_rva(rva)}",
                rva,
            )
            continue

        view, issue = _instruction_view(instruction, image_base=image_base)
        views[rva] = view
        if issue is not None:
            issues[rva] = issue
        for successor in view.successors:
            enqueue(successor, rva)

    if budget_issue is not None:
        issues[budget_issue.rva] = budget_issue

    seed_provenance = _seed_provenance(
        seeds=seeds,
        reached=reached,
        views=views,
    )

    issue_rows = [
        _issue_payload(issue, seeds, incoming, seed_provenance)
        for issue in sorted(
            issues.values(),
            key=lambda item: (item.rva, item.code, item.message),
        )
    ]
    return {
        "format": ROOTED_INSTRUCTION_VIEW_FORMAT,
        "status": "incomplete" if issue_rows else "complete",
        "instruction_budget": budget,
        "decoded_instruction_count": len(views),
        "views": [
            _view_payload(view, seeds, incoming, seed_provenance)
            for view in sorted(views.values(), key=lambda item: item.rva_start)
        ],
        "merge_destinations": [
            {
                "rva": rva,
                "provenance": _provenance_payload(
                    rva, seeds, incoming, seed_provenance
                ),
            }
            for rva in sorted(merges)
        ],
        "issues": issue_rows,
    }


def _instruction_view(
    instruction: capstone.CsInsn, *, image_base: int
) -> tuple[_View, _Issue | None]:
    rva = int(instruction.address) - image_base
    end = rva + int(instruction.size)
    mnemonic = instruction.mnemonic.lower()
    successors: tuple[_Successor, ...] = ()
    issue: _Issue | None = None

    if instruction.id in _FAR_CONTROL_IDS or mnemonic in {
        "lcall",
        "ljmp",
        "retf",
        "retfq",
    }:
        control_kind = "unsupported_far_control"
        issue = _Issue(
            "unsupported_far_control",
            f"unsupported far control {mnemonic} at RVA {_format_rva(rva)}",
            rva,
        )
    elif (
        mnemonic in _SYSTEM_CONTROL_MNEMONICS
        or instruction.group(capstone.CS_GRP_INT)
        or instruction.group(capstone.CS_GRP_IRET)
        or instruction.group(capstone.CS_GRP_PRIVILEGE)
    ):
        control_kind = "unsupported_system_control"
        issue = _Issue(
            "unsupported_system_control",
            f"unsupported system control {mnemonic} at RVA {_format_rva(rva)}",
            rva,
        )
    elif instruction.group(capstone.CS_GRP_RET):
        control_kind = "return"
    elif instruction.group(capstone.CS_GRP_CALL):
        target = _direct_target(instruction, image_base=image_base)
        if target is None:
            control_kind = "indirect_call"
            successors = (_Successor("call_continuation", end),)
        else:
            control_kind = "direct_call"
            successors = (
                _Successor("call_target", target),
                _Successor("call_continuation", end),
            )
    elif instruction.group(capstone.CS_GRP_JUMP):
        target = _direct_target(instruction, image_base=image_base)
        if target is None:
            control_kind = "indirect_jump"
        elif instruction.id == x86_const.X86_INS_JMP:
            control_kind = "direct_jump"
            successors = (_Successor("jump", target),)
        else:
            control_kind = "conditional_branch"
            successors = (
                _Successor("branch_taken", target),
                _Successor("branch_fallthrough", end),
            )
    else:
        control_kind = "fallthrough"
        successors = (_Successor("fallthrough", end),)

    return (
        _View(
            rva_start=rva,
            rva_end=end,
            encoded=bytes(instruction.bytes),
            mnemonic=mnemonic,
            op_str=instruction.op_str,
            control_kind=control_kind,
            successors=successors,
        ),
        issue,
    )


def _decode_one(
    decoder: capstone.Cs,
    reader: Any,
    *,
    image_base: int,
    rva: int,
    section_end: int,
) -> capstone.CsInsn | None:
    width = min(_MAX_INSTRUCTION_SIZE, section_end - rva)
    if width <= 0:
        return None
    try:
        data = bytes(reader(rva, width))[:width]
    except Exception:  # The binary/read adapter is an untrusted proposal input.
        return None
    if not data:
        return None
    try:
        instruction = next(
            iter(decoder.disasm(data, image_base + rva, count=1)),
            None,
        )
    except (capstone.CsError, ValueError):
        return None
    if (
        instruction is None
        or int(instruction.address) != image_base + rva
        or int(instruction.size) <= 0
        or rva + int(instruction.size) > section_end
    ):
        return None
    return instruction


def _direct_target(instruction: capstone.CsInsn, *, image_base: int) -> int | None:
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != x86_const.X86_OP_IMM:
        return None
    target_va = int(operands[0].imm) & (_U32_LIMIT - 1)
    return target_va - image_base


def _seed_provenance(
    *,
    seeds: frozenset[int],
    reached: set[int],
    views: Mapping[int, _View],
) -> dict[int, set[int]]:
    provenance = {rva: set() for rva in reached}
    for seed in seeds:
        if seed in provenance:
            provenance[seed].add(seed)

    changed = True
    while changed:
        changed = False
        for source in sorted(views):
            source_seeds = provenance.get(source, set())
            if not source_seeds:
                continue
            for successor in views[source].successors:
                target_seeds = provenance.get(successor.target_rva)
                if target_seeds is None or source_seeds.issubset(target_seeds):
                    continue
                target_seeds.update(source_seeds)
                changed = True
    return provenance


def _view_payload(
    view: _View,
    seeds: frozenset[int],
    incoming: Mapping[int, set[_Predecessor]],
    seed_provenance: Mapping[int, set[int]],
) -> dict[str, Any]:
    return {
        "rva_start": view.rva_start,
        "rva_end": view.rva_end,
        "bytes": view.encoded.hex(),
        "mnemonic": view.mnemonic,
        "op_str": view.op_str,
        "control": {
            "kind": view.control_kind,
            "successors": [
                {"kind": successor.kind, "target_rva": successor.target_rva}
                for successor in view.successors
            ],
        },
        "provenance": _provenance_payload(
            view.rva_start, seeds, incoming, seed_provenance
        ),
    }


def _issue_payload(
    issue: _Issue,
    seeds: frozenset[int],
    incoming: Mapping[int, set[_Predecessor]],
    seed_provenance: Mapping[int, set[int]],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "incomplete",
        "code": issue.code,
        "message": issue.message,
        "rva": issue.rva,
        "provenance": _provenance_payload(
            issue.rva, seeds, incoming, seed_provenance
        ),
    }
    if issue.pending_rvas:
        payload["pending_rvas"] = list(issue.pending_rvas)
    return payload


def _provenance_payload(
    rva: int,
    seeds: frozenset[int],
    incoming: Mapping[int, set[_Predecessor]],
    seed_provenance: Mapping[int, set[int]],
) -> dict[str, Any]:
    predecessors = sorted(
        incoming.get(rva, ()),
        key=lambda item: (
            item.source_rva,
            _EDGE_ORDER.get(item.edge_kind, len(_EDGE_ORDER)),
            item.edge_kind,
        ),
    )
    return {
        "is_seed": rva in seeds,
        "seed_rvas": sorted(seed_provenance.get(rva, ())),
        "predecessors": [
            {"source_rva": item.source_rva, "edge_kind": item.edge_kind}
            for item in predecessors
        ],
    }


def _sections(binary: Any) -> tuple[Any, ...]:
    value = _field(binary, "sections")
    if not isinstance(value, Sequence):
        raise TypeError("binary sections must be a finite sequence")
    return tuple(value)


def _executable_section_end(sections: Sequence[Any], rva: int) -> int | None:
    matches: list[tuple[int, int]] = []
    for section in sections:
        if not bool(_field(section, "executable")):
            continue
        start = _integer_field(section, "rva_start")
        end = _integer_field(section, "rva_end")
        if start <= rva < end:
            matches.append((end, start))
    return min(matches)[0] if matches else None


def _reader(binary: Any) -> Any:
    for owner, name in (
        (binary, "read_rva"),
        (binary, "get_data"),
        (_field(binary, "pe", default=None), "get_data"),
    ):
        candidate = getattr(owner, name, None) if owner is not None else None
        if callable(candidate):
            return candidate
    raise TypeError(
        "binary must expose read_rva, get_data, or pe.get_data for RVA reads"
    )


def _rva_values(values: Iterable[int], label: str) -> tuple[int, ...]:
    try:
        return tuple(_index(value, label) for value in values)
    except TypeError:
        raise
    except Exception as error:
        raise TypeError(f"{label} must be a finite iterable of integers") from error


def _integer_field(value: Any, name: str) -> int:
    return _index(_field(value, name), name)


def _field(value: Any, name: str, *, default: Any = ...) -> Any:
    if isinstance(value, Mapping):
        if name in value:
            return value[name]
    elif hasattr(value, name):
        return getattr(value, name)
    if default is not ...:
        return default
    raise TypeError(f"binary view is missing required field {name!r}")


def _index(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{label} must contain integers, not booleans")
    try:
        return operator.index(value)
    except TypeError as error:
        raise TypeError(f"{label} must contain integers") from error


def _format_rva(rva: int) -> str:
    return f"0x{rva:x}" if rva >= 0 else f"-0x{-rva:x}"
