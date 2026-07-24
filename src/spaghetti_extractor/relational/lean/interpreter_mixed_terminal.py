"""Load untrusted terminating-boundary proposals for mixed reachability.

The machine-import report is diagnostic input, not proof authority.  This
module only rejects stale or ambiguous reports and extracts candidate terminal
cuts.  Generated Lean must still validate every selected boundary against the
exact PE, import table, route certificate, and terminating machine contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from .static_machine_import_contracts import STATIC_MACHINE_IMPORT_FORMAT


class InterpreterMixedTerminalProposalError(StageAInputError):
    """A machine-import report cannot safely propose terminal cuts."""


@dataclass(frozen=True, order=True)
class InterpreterMixedTerminalProposal:
    boundary_id: int
    signature_id: int
    source_rva: int
    source_size: int
    instruction_rva: int
    execution_source_rva: int
    continuation_rva: int


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InterpreterMixedTerminalProposalError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise InterpreterMixedTerminalProposalError(f"{context} must be an array")
    return value


def _nat(value: object, context: str, *, positive: bool = False) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < (1 if positive else 0)
        or value >= 2**32
    ):
        qualifier = "positive " if positive else ""
        raise InterpreterMixedTerminalProposalError(
            f"{context} must be a {qualifier}PE32 integer"
        )
    return value


def _hash(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise InterpreterMixedTerminalProposalError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def load_interpreter_mixed_terminal_proposals(
    report_path: Path | str,
    *,
    original_sha256: str,
    reference_contract_sha256: str,
    state_machine_sha256: str,
) -> tuple[InterpreterMixedTerminalProposal, ...]:
    """Extract hash-matched, unique terminal-boundary proposals.

    No report status or verdict field is consumed.  Returning and protocol
    boundaries are deliberately absent from the result.
    """

    path = Path(report_path)
    if not path.is_file() or path.is_symlink():
        raise InterpreterMixedTerminalProposalError(
            f"machine-import report is not a regular file: {path}"
        )
    try:
        payload = _mapping(json.loads(path.read_text(encoding="utf-8")), "report")
    except (OSError, json.JSONDecodeError) as error:
        raise InterpreterMixedTerminalProposalError(
            f"unable to read machine-import report: {path}"
        ) from error
    if payload.get("format") != STATIC_MACHINE_IMPORT_FORMAT:
        raise InterpreterMixedTerminalProposalError(
            "machine-import report has the wrong format"
        )

    expected_hashes = {
        "original_sha256": _hash(original_sha256, "expected original SHA-256"),
        "reference_contract_sha256": _hash(
            reference_contract_sha256, "expected reference-contract SHA-256"
        ),
        "state_machine_sha256": _hash(
            state_machine_sha256, "expected state-machine SHA-256"
        ),
    }
    inputs = _mapping(payload.get("inputs"), "report.inputs")
    for key, expected in expected_hashes.items():
        observed = _hash(inputs.get(key), f"report.inputs.{key}")
        if observed != expected:
            raise InterpreterMixedTerminalProposalError(
                f"machine-import report {key} does not match the current artifact"
            )

    dispositions: dict[int, str] = {}
    for index, value in enumerate(_array(payload.get("signatures"), "signatures")):
        signature = _mapping(value, f"signatures[{index}]")
        signature_id = _nat(signature.get("id"), f"signatures[{index}].id")
        if signature_id in dispositions:
            raise InterpreterMixedTerminalProposalError(
                f"duplicate machine-import signature id {signature_id}"
            )
        disposition = signature.get("disposition")
        if disposition not in {"returns", "terminates", "protocol"}:
            raise InterpreterMixedTerminalProposalError(
                f"signatures[{index}].disposition is unsupported"
            )
        dispositions[signature_id] = disposition

    proposals: list[InterpreterMixedTerminalProposal] = []
    boundary_ids: set[int] = set()
    boundary_keys: set[tuple[int, int, int]] = set()
    for index, value in enumerate(_array(payload.get("boundaries"), "boundaries")):
        boundary = _mapping(value, f"boundaries[{index}]")
        boundary_id = _nat(boundary.get("id"), f"boundaries[{index}].id")
        if boundary_id in boundary_ids:
            raise InterpreterMixedTerminalProposalError(
                f"duplicate machine-import boundary id {boundary_id}"
            )
        boundary_ids.add(boundary_id)
        signature_id = _nat(
            boundary.get("signature_id"), f"boundaries[{index}].signature_id"
        )
        if signature_id not in dispositions:
            raise InterpreterMixedTerminalProposalError(
                f"boundaries[{index}] names missing signature {signature_id}"
            )
        source_rva = _nat(
            boundary.get("source_rva"), f"boundaries[{index}].source_rva"
        )
        source_size = _nat(
            boundary.get("source_size"),
            f"boundaries[{index}].source_size",
            positive=True,
        )
        if source_rva + source_size > 2**32:
            raise InterpreterMixedTerminalProposalError(
                f"boundaries[{index}] source span overflows PE32"
            )
        instruction_rva = _nat(
            boundary.get("instruction_rva"),
            f"boundaries[{index}].instruction_rva",
        )
        execution_source_rva = _nat(
            boundary.get("execution_source_rva"),
            f"boundaries[{index}].execution_source_rva",
        )
        continuation_rva = _nat(
            boundary.get("continuation_rva"),
            f"boundaries[{index}].continuation_rva",
        )
        key = (source_rva, continuation_rva, signature_id)
        if key in boundary_keys:
            raise InterpreterMixedTerminalProposalError(
                "ambiguous machine-import boundaries share source, continuation, "
                "and signature"
            )
        boundary_keys.add(key)
        if dispositions[signature_id] == "terminates":
            proposals.append(
                InterpreterMixedTerminalProposal(
                    boundary_id=boundary_id,
                    signature_id=signature_id,
                    source_rva=source_rva,
                    source_size=source_size,
                    instruction_rva=instruction_rva,
                    execution_source_rva=execution_source_rva,
                    continuation_rva=continuation_rva,
                )
            )
    return tuple(sorted(proposals))


__all__ = [
    "InterpreterMixedTerminalProposal",
    "InterpreterMixedTerminalProposalError",
    "load_interpreter_mixed_terminal_proposals",
]
