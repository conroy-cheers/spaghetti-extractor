from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest

from spaghetti_extractor.stage_b_native_diagnostic import (
    StageBNativeDiagnosticError,
    decode_stage_b_native_diagnostic,
    decode_stage_b_native_diagnostic_file,
)


def _diagnostic(
    *,
    reason: int = 0x2009,
    transfer_rows: list[tuple[int, int, int, int]] | None = None,
    transfer_next: int | None = None,
) -> bytes:
    transfers = transfer_rows or [(1, 0x1000, 0, 0x220000)]
    next_index = len(transfers) if transfer_next is None else transfer_next
    header = [
        0x31444553,
        4,
        1,
        0x130BE,
        reason,
        0x130BE,
        0x7BF589D0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        len(transfers),
        next_index,
        max(row[0] for row in transfers),
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        0x220000,
        0x202,
        0x7FFDE000,
        2,
        0x11111111,
        0x22222222,
        *([0] * 14),
    ]
    return struct.pack("<45I", *header) + b"".join(
        struct.pack("<4I", *row) for row in transfers
    )


class StageBNativeDiagnosticTests(unittest.TestCase):
    def test_decodes_failure_and_binds_exact_static_site(self) -> None:
        data = _diagnostic()
        engine = {
            "external_sites": [{
                "instruction_rva": 0x130BE,
                "transfer_id": "semantic-transfer:site",
                "target_expression": {"op": "reg", "name": "ebx", "width": 32},
            }],
            "diagnostic_frontiers": [{
                "instruction_rva": 0x130BE,
                "category": "external_site_contract_deferred",
            }],
        }
        runtime = {
            "inputs": {
                "external_dispatch": {
                    "blocked_sites": [{
                        "instruction_rva": 0x130BE,
                        "category": "uncontracted_dynamic_external_target",
                    }]
                }
            }
        }

        report = decode_stage_b_native_diagnostic(
            data,
            native_engine_plan=engine,
            native_runtime_package=runtime,
        )

        self.assertEqual(report["status"], "decoded")
        self.assertFalse(report["proof_authority"])
        self.assertEqual(report["failure"]["category"], "external_site_not_authorized")
        self.assertEqual(report["failure"]["rva_hex"], "0x000130be")
        self.assertEqual(report["failure"]["aux_hex"], "0x7bf589d0")
        self.assertEqual(report["failure"]["registers"]["ebx"]["value"], 2)
        self.assertEqual(
            report["static_context"]["external_sites"][0]["transfer_id"],
            "semantic-transfer:site",
        )
        self.assertEqual(
            report["static_context"]["blocked_external_sites"][0]["category"],
            "uncontracted_dynamic_external_target",
        )

    def test_decodes_file_and_rejects_trailing_or_truncated_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            diagnostic = root / "diagnostic.bin"
            engine = root / "engine.json"
            runtime = root / "runtime.json"
            diagnostic.write_bytes(_diagnostic())
            engine.write_text(json.dumps({"external_sites": []}), encoding="utf-8")
            runtime.write_text(json.dumps({"inputs": {}}), encoding="utf-8")

            report = decode_stage_b_native_diagnostic_file(
                diagnostic,
                native_engine_plan=engine,
                native_runtime_package=runtime,
            )
            self.assertRegex(
                report["static_context"]["native_engine_plan_sha256"],
                r"^[0-9a-f]{64}$",
            )
            with self.assertRaisesRegex(StageBNativeDiagnosticError, "expected"):
                decode_stage_b_native_diagnostic(_diagnostic() + b"extra")
            with self.assertRaisesRegex(StageBNativeDiagnosticError, "shorter"):
                decode_stage_b_native_diagnostic(b"short")

    def test_full_ring_is_normalized_from_oldest_to_newest(self) -> None:
        rows = [
            (index + 1, 0x1000 + index, 0, 0x220000 - index * 4)
            for index in range(1024)
        ]
        report = decode_stage_b_native_diagnostic(
            _diagnostic(transfer_rows=rows, transfer_next=3)
        )
        trace = report["transfer_trace"]
        self.assertEqual(trace[0]["sequence"], 4)
        self.assertEqual(trace[-1]["sequence"], 3)
        self.assertEqual(len(trace), 1024)

    def test_partial_ring_rejects_inconsistent_next_index(self) -> None:
        with self.assertRaisesRegex(StageBNativeDiagnosticError, "next index"):
            decode_stage_b_native_diagnostic(
                _diagnostic(transfer_next=0)
            )


if __name__ == "__main__":
    unittest.main()
