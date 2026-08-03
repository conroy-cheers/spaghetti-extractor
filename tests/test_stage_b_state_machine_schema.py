from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_state_machine import (
    STAGE_A_SEMANTIC_IR_MODEL,
    STAGE_A_SEMANTIC_TRANSFER_FORMAT,
    StageAReferenceContractBinding,
    _load_stage_a_semantic_transfer_rows,
    normalize_stage_a_semantic_transfer,
)


class StageBStateMachineSchemaTests(unittest.TestCase):
    def test_blocking_instruction_is_preserved_as_hash_bound_diagnostic(self) -> None:
        row = _blocked_transfer()

        normalized = normalize_stage_a_semantic_transfer(row)
        self.assertEqual(normalized["blocking_instruction"], row["blocking_instruction"])

        changed = _blocked_transfer()
        changed["blocking_instruction"] = {
            **changed["blocking_instruction"],
            "mnemonic": "different",
        }
        self.assertNotEqual(
            normalized["contract_sha256"],
            normalize_stage_a_semantic_transfer(changed)["contract_sha256"],
        )

    def test_public_export_loader_accepts_explicit_blocking_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sidecar = root / "semantic-transfer-contracts.jsonl"
            reference_path = root / "reference-contract.json"
            reference_path.write_text("{}\n", encoding="ascii")
            reference_sha256 = hashlib.sha256(b"{}\n").hexdigest()
            row = {
                **_blocked_transfer(),
                "reference_contract": {
                    "format": "stage-a-reference-contract-v1",
                    "sha256": reference_sha256,
                },
            }
            sidecar.write_text(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            reference = StageAReferenceContractBinding(
                path=reference_path,
                sha256=reference_sha256,
                original_pe_sha256="0" * 64,
                semantic_transfer_contracts=sidecar,
            )

            loaded = _load_stage_a_semantic_transfer_rows(sidecar, reference)

        self.assertEqual(len(loaded), 1)
        self.assertEqual(
            loaded[0]["blocking_instruction"]["mnemonic"], "unsupported"
        )


def _blocked_transfer() -> dict[str, object]:
    empty_digest = hashlib.sha256(b"").hexdigest()
    return {
        "format": STAGE_A_SEMANTIC_TRANSFER_FORMAT,
        "id": "semantic-transfer:blocked",
        "function": "fixture",
        "block_id": "block:fixture",
        "unit_kind": "basic_block",
        "status": "incomplete",
        "reachable": True,
        "original": {"rva_start": 0x1000, "rva_end": 0x1000, "size": 0},
        "instructions": [],
        "instruction_bytes_sha256": empty_digest,
        "expression_model": STAGE_A_SEMANTIC_IR_MODEL,
        "pre_state": {},
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "outcome": {"kind": "unknown"},
        "stack_delta": None,
        "fpu_state": None,
        "counts": {
            "register_writes": 0,
            "flag_writes": 0,
            "memory_events": 0,
            "external_events": 0,
            "faults": 0,
            "ordered_events": 0,
            "edge_conditions": 0,
        },
        "acceptance": "guidance only",
        "blocker_category": "unsupported_semantics",
        "blocker": "fixture unsupported instruction",
        "next_action": "add checked semantics",
        "blocking_instruction": {
            "rva": 0x1000,
            "mnemonic": "unsupported",
            "op_str": "",
            "bytes": "0f0b",
        },
    }


if __name__ == "__main__":
    unittest.main()
