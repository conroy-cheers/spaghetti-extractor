from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_terminal import (
    InterpreterMixedTerminalProposalError,
    load_interpreter_mixed_terminal_proposals,
)
from spaghetti_extractor.relational.lean.static_machine_import_contracts import (
    STATIC_MACHINE_IMPORT_FORMAT,
)


_A = "a" * 64
_B = "b" * 64
_C = "c" * 64


def _report() -> dict[str, object]:
    return {
        "format": STATIC_MACHINE_IMPORT_FORMAT,
        "status": "pass-is-not-authority",
        "inputs": {
            "original_sha256": _A,
            "reference_contract_sha256": _B,
            "state_machine_sha256": _C,
        },
        "signatures": [
            {"id": 1, "disposition": "returns"},
            {"id": 2, "disposition": "terminates"},
            {"id": 3, "disposition": "protocol"},
        ],
        "boundaries": [
            {
                "id": 10,
                "signature_id": 1,
                "source_rva": 0x1000,
                "source_size": 5,
                "instruction_rva": 0x1000,
                "execution_source_rva": 0x2000,
                "continuation_rva": 0x1005,
            },
            {
                "id": 11,
                "signature_id": 2,
                "source_rva": 0x1100,
                "source_size": 5,
                "instruction_rva": 0x1100,
                "execution_source_rva": 0x2000,
                "continuation_rva": 0x1105,
            },
            {
                "id": 12,
                "signature_id": 3,
                "source_rva": 0x1200,
                "source_size": 5,
                "instruction_rva": 0x1200,
                "execution_source_rva": 0x2000,
                "continuation_rva": 0x1205,
            },
        ],
    }


class StageAInterpreterMixedTerminalProposalTests(unittest.TestCase):
    def _load(self, payload: dict[str, object]):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_interpreter_mixed_terminal_proposals(
                path,
                original_sha256=_A,
                reference_contract_sha256=_B,
                state_machine_sha256=_C,
            )

    def test_only_hash_matched_terminating_boundaries_are_proposed(self) -> None:
        proposals = self._load(_report())

        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].boundary_id, 11)
        self.assertEqual(proposals[0].source_rva, 0x1100)
        self.assertEqual(proposals[0].continuation_rva, 0x1105)

    def test_stale_artifact_hashes_fail_closed(self) -> None:
        for key in (
            "original_sha256",
            "reference_contract_sha256",
            "state_machine_sha256",
        ):
            payload = _report()
            payload["inputs"][key] = "d" * 64  # type: ignore[index]
            with self.subTest(key=key), self.assertRaisesRegex(
                InterpreterMixedTerminalProposalError, "does not match"
            ):
                self._load(payload)

    def test_duplicate_or_ambiguous_boundaries_fail_closed(self) -> None:
        duplicate_id = _report()
        duplicate_id["boundaries"].append(  # type: ignore[union-attr]
            deepcopy(duplicate_id["boundaries"][0])  # type: ignore[index]
        )
        with self.assertRaisesRegex(
            InterpreterMixedTerminalProposalError, "duplicate.*boundary"
        ):
            self._load(duplicate_id)

        ambiguous = _report()
        duplicate = deepcopy(ambiguous["boundaries"][1])  # type: ignore[index]
        duplicate["id"] = 99
        ambiguous["boundaries"].append(duplicate)  # type: ignore[union-attr]
        with self.assertRaisesRegex(
            InterpreterMixedTerminalProposalError, "ambiguous.*boundaries"
        ):
            self._load(ambiguous)

    def test_missing_signature_and_bad_span_fail_closed(self) -> None:
        missing = _report()
        missing["boundaries"][0]["signature_id"] = 99  # type: ignore[index]
        with self.assertRaisesRegex(
            InterpreterMixedTerminalProposalError, "missing signature"
        ):
            self._load(missing)

        overflow = _report()
        overflow["boundaries"][0]["source_rva"] = 2**32 - 1  # type: ignore[index]
        overflow["boundaries"][0]["source_size"] = 2  # type: ignore[index]
        with self.assertRaisesRegex(
            InterpreterMixedTerminalProposalError, "overflows PE32"
        ):
            self._load(overflow)


if __name__ == "__main__":
    unittest.main()
