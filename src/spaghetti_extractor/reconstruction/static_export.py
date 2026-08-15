"""Original-only static reconstruction export orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..errors import ToolkitInputError
from ..static_program.extraction import (
    STATIC_PROGRAM_EXPORT_FORMAT,
    spx_export_static_program,
)
from ..util import write_json
from .state_machine import write_state_machine_from_static_program


def export_static_reconstruction(
    *, original: Path, inventory: Path, out: Path
) -> dict[str, Any]:
    """Emit an original-only static program plus its canonical state machine."""

    original = Path(original).resolve()
    out = Path(out).resolve()
    manifest = spx_export_static_program(
        original=original,
        inventory=Path(inventory),
        out=out,
    )
    if manifest.get("format") != STATIC_PROGRAM_EXPORT_FORMAT:
        raise ToolkitInputError("static-program export returned an unexpected format")

    contract_path = out / "static-program-contract.json"
    semantic_path = out / "semantic-transfer-contracts.jsonl"
    state_machine_path = out / "state-machine.jsonl"
    binding = write_state_machine_from_static_program(
        static_program_contract=contract_path,
        semantic_transfer_contracts=semantic_path,
        original_pe=original,
        out=state_machine_path,
    )

    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        raise ToolkitInputError("static-program export has malformed outputs")
    outputs["state_machine"] = {
        "path": state_machine_path.name,
        "sha256": binding.sha256,
        "static_program_contract_sha256": binding.static_program_contract_sha256,
        "semantic_transfer_contracts_sha256": (
            binding.semantic_transfer_contracts_sha256
        ),
    }
    counts = manifest.get("counts")
    if isinstance(counts, dict):
        counts["state_machine_transfers"] = binding.transfer_count
    write_json(out / "static-program-export.json", manifest)
    return manifest


__all__ = ["export_static_reconstruction"]
