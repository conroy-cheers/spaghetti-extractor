"""Toolchain-scoped symbol decoration evidence for PE32 call boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from ..authority.parametric_summary_records import PE32_CALLEE_PRESERVED_REGISTERS_V3
from .model import (
    AbiEvidenceV1,
    AbiFactV1,
    AbiLocationV1,
    AbiValueV1,
    PE32_TARGET_V1,
    StackCleanupV1,
    VariadicPolicyV1,
)


_STDCALL = re.compile(r"^_?([A-Za-z_$][A-Za-z0-9_$?]*)@([0-9]+)$")
_FASTCALL = re.compile(r"^@([A-Za-z_$][A-Za-z0-9_$?]*)@([0-9]+)$")
_CDECL = re.compile(r"^_([A-Za-z_$][A-Za-z0-9_$?.]*)$")
_COMPILER_LOCAL_SUFFIX = re.compile(
    r"\.(?:part|constprop|isra|cold|hot|clone)(?:\.[A-Za-z0-9_$?]+)*$"
)


@dataclass(frozen=True)
class SymbolAbiEvidenceV1:
    evidence: AbiEvidenceV1
    facts: tuple[AbiFactV1, ...]
    undecorated_symbol: str
    confidence: str


def _fact(
    subject_id: str, field: str, value: object, evidence_id: str
) -> AbiFactV1:
    return AbiFactV1.create(
        subject_id=subject_id,
        field=field,
        status="exact",
        values=(value,),
        evidence_ids=(evidence_id,),
    )


def _stack_value(index: int, *, offset: int) -> AbiValueV1:
    return AbiValueV1(
        f"arg{index}",
        32,
        "ordinary",
        (AbiLocationV1("stack", 32, stack_offset=offset),),
    )


def infer_pe32_symbol_abi(
    *,
    subject_id: str,
    subject_kind: str,
    symbols: Iterable[str],
    decoration_model: str,
    dependency_ids: Iterable[str] = (),
) -> SymbolAbiEvidenceV1 | None:
    """Return finite physical facts implied by one pinned decoration model.

    Names are hints unless the catalog declaration pins the producer's symbol
    decoration model.  Cdecl decoration does not encode arity or varargs, so
    those fields intentionally remain unresolved.
    """

    if decoration_model not in {"pe32-coff-gnu-v1", "pe32-coff-msvc-v1"}:
        raise ValueError(f"unsupported symbol decoration model {decoration_model!r}")
    candidates: list[tuple[str, str, int | None]] = []
    for symbol in sorted(set(symbols)):
        match = _FASTCALL.fullmatch(symbol)
        if match is not None:
            candidates.append((match.group(1), "fastcall", int(match.group(2))))
            continue
        match = _STDCALL.fullmatch(symbol)
        if match is not None:
            candidates.append((match.group(1), "stdcall", int(match.group(2))))
            continue
        match = _CDECL.fullmatch(symbol)
        if match is not None:
            undecorated = match.group(1)
            # COFF import-address symbols describe data slots, not callable
            # function bodies. A real C identifier may itself begin with one
            # or more underscores, so all other names lose exactly the one
            # decoration underscore.
            if (
                not undecorated.startswith("_imp_")
                and _COMPILER_LOCAL_SUFFIX.search(undecorated) is None
            ):
                candidates.append((undecorated, "cdecl", None))
    unique = sorted(set(candidates))
    if len(unique) != 1:
        return None
    undecorated, convention, byte_count = unique[0]
    evidence = AbiEvidenceV1.create(
        kind="pinned_symbol_decoration",
        producer=decoration_model,
        subject_kind=subject_kind,
        subject_id=subject_id,
        dependencies=dependency_ids,
        payload={
            "symbols": sorted(set(symbols)),
            "undecorated_symbol": undecorated,
            "calling_convention": convention,
            "encoded_argument_bytes": byte_count,
        },
    )
    facts = [
        _fact(subject_id, "target", PE32_TARGET_V1.to_payload(), evidence.evidence_id),
        _fact(subject_id, "stack_coordinate", "callee_entry_esp_v1", evidence.evidence_id),
        _fact(subject_id, "stack_alignment_bytes", 4, evidence.evidence_id),
        _fact(subject_id, "calling_convention", convention, evidence.evidence_id),
        _fact(
            subject_id,
            "preserved_state",
            list(PE32_CALLEE_PRESERVED_REGISTERS_V3),
            evidence.evidence_id,
        ),
    ]
    if convention == "cdecl":
        facts.append(
            _fact(
                subject_id,
                "stack_cleanup",
                StackCleanupV1("caller", 0).to_payload(),
                evidence.evidence_id,
            )
        )
    else:
        assert byte_count is not None
        if byte_count % 4 != 0:
            return None
        count = byte_count // 4
        arguments: list[AbiValueV1] = []
        stack_words = count
        if convention == "fastcall":
            register_arguments = ("ecx", "edx")[:count]
            for index, register in enumerate(register_arguments):
                arguments.append(
                    AbiValueV1(
                        f"arg{index}",
                        32,
                        "ordinary",
                        (AbiLocationV1("register", 32, register=register),),
                    )
                )
            stack_words -= len(register_arguments)
        for stack_index in range(stack_words):
            argument_index = len(arguments)
            arguments.append(
                _stack_value(argument_index, offset=4 + stack_index * 4)
            )
        cleanup_bytes = stack_words * 4 if convention == "fastcall" else byte_count
        facts.extend(
            (
                _fact(
                    subject_id,
                    "arguments",
                    [item.to_payload() for item in arguments],
                    evidence.evidence_id,
                ),
                _fact(
                    subject_id,
                    "stack_cleanup",
                    StackCleanupV1("callee", cleanup_bytes).to_payload(),
                    evidence.evidence_id,
                ),
                _fact(
                    subject_id,
                    "variadic",
                    VariadicPolicyV1("none", len(arguments)).to_payload(),
                    evidence.evidence_id,
                ),
            )
        )
    return SymbolAbiEvidenceV1(
        evidence,
        tuple(sorted(facts, key=lambda item: item.field)),
        undecorated,
        "strong" if byte_count is not None else "partial",
    )


__all__ = ["SymbolAbiEvidenceV1", "infer_pe32_symbol_abi"]
