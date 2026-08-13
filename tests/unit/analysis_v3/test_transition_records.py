from __future__ import annotations

import copy
import hashlib
import unittest

from spaghetti_extractor.analysis_v3._schema import AnalysisV3Error
from spaghetti_extractor.analysis_v3.exact_units import ExactUnitV3
from spaghetti_extractor.analysis_v3.transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionExitV3,
    TransitionMemoryAccessV3,
    TransitionSummaryRecordV3,
)
from spaghetti_extractor.analysis_v3.transition_summaries import _derive_summary
from spaghetti_extractor.artifact_set_v3 import (
    canonical_json_bytes_v3,
)


PE_SHA256 = "a" * 64


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _unit() -> dict[str, object]:
    memory_event = {
        "kind": "write",
        "width": 4,
        "instruction_rva": 0x1001,
        "address": _const(0x401000),
        "value": _reg("eax"),
    }
    external_event = {
        "kind": "import_call",
        "instruction_rva": 0x1002,
        "dll": "KERNEL32.dll",
        "symbol": "GetLastError",
        "arguments": [],
    }
    fault = {
        "kind": "divide_error",
        "instruction_rva": 0x1003,
        "predicate": {"op": "eq", "args": [_reg("ecx"), _const(0)]},
    }
    semantics = {
        "pre_state": {
            "registers": {"eax": _reg("eax")},
            "flags": {},
            "memory": {
                "op": "memory",
                "name": "mem0",
                "address_width": 32,
                "value_width": 8,
            },
        },
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [memory_event],
        "external_events": [external_event],
        "faults": [fault],
        "ordered_events": [memory_event],
        "edge_conditions": [],
        "outcome": {"kind": "return"},
        "stack_delta": None,
        "counts": {
            "register_writes": 0,
            "flag_writes": 0,
            "memory_events": 1,
            "external_events": 1,
            "faults": 1,
            "ordered_events": 1,
            "edge_conditions": 0,
        },
    }
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:entry",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1008},
            "instruction_bytes_sha256": "c" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": semantics,
        "control": {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


class TransitionRecordV3Tests(unittest.TestCase):
    def _exact_and_native(self) -> tuple[ExactUnitV3, TransitionSummaryRecordV3]:
        exact = ExactUnitV3.create(_unit(), pe_sha256=PE_SHA256)
        return exact, _derive_summary(exact)

    def test_native_generation_preserves_canonical_bytes_and_ids(self) -> None:
        exact, native = self._exact_and_native()
        encoded = TRANSITION_SUMMARY_CODEC_V3.encode(native)

        self.assertEqual(encoded["id"], exact.record_id)
        self.assertEqual(encoded["unit_ir_sha256"], exact.unit_ir_sha256)
        self.assertEqual(
            hashlib.sha256(canonical_json_bytes_v3(encoded)).hexdigest(),
            "7ea0b27c29745c002bce91ecfeb895f73475717477e16184dd9131d285f5fc84",
        )
        self.assertEqual(
            native.summary_id,
            "transition-summary:959cfec62603990b009b5438",
        )
        self.assertEqual(
            tuple(row.input_id for row in native.inputs),
            (
                "transition-input:ab741266b60ea2a0dcf925a0",
                "transition-input:f8fdf6542267c35fd4ea07f1",
            ),
        )
        self.assertEqual(
            native.memory_accesses[0].access_id,
            "transition-memory:709f81449d16a6ea3f2428b5",
        )
        self.assertEqual(
            tuple(row.exit_id for row in native.exits),
            (
                "transition-exit:e01dd21e11a46b0b6fb0cfa9",
                "transition-exit:ce9f54df0ddcb1f759f5f75e",
            ),
        )
        self.assertEqual(
            native.faults[0].fault_id,
            "transition-fault:bbcad39907c34b9cec161fb3",
        )
        self.assertEqual(
            native.ordered_events[0].record_id,
            "transition-record:1532b6255874ea7fe8df0c01",
        )

    def test_native_codec_round_trip_uses_native_record_types(self) -> None:
        _exact, native = self._exact_and_native()
        payload = TRANSITION_SUMMARY_CODEC_V3.encode(native)
        decoded = TRANSITION_SUMMARY_CODEC_V3.decode(payload)

        self.assertEqual(decoded, native)
        self.assertIsInstance(decoded, TransitionSummaryRecordV3)
        self.assertIsInstance(decoded.memory_accesses[0], TransitionMemoryAccessV3)
        self.assertIsInstance(decoded.exits[0], TransitionExitV3)
        self.assertIs(decoded.parsed_summary, decoded)

    def test_nested_schema_and_identity_corruption_fail_closed(self) -> None:
        _exact, native = self._exact_and_native()
        payload = TRANSITION_SUMMARY_CODEC_V3.encode(native)

        extra_binding = copy.deepcopy(payload)
        extra_binding["memory_accesses"][0]["binding"]["unit"] = {}
        with self.assertRaises(AnalysisV3Error) as raised:
            TRANSITION_SUMMARY_CODEC_V3.decode(extra_binding)
        self.assertEqual(raised.exception.code, "record_schema_mismatch")

        stale_nested_id = copy.deepcopy(payload)
        stale_nested_id["memory_accesses"][0]["width_bytes"] = 8
        with self.assertRaises(AnalysisV3Error) as raised:
            TRANSITION_SUMMARY_CODEC_V3.decode(stale_nested_id)
        self.assertEqual(raised.exception.code, "stale_record_id")

        stale_summary_id = copy.deepcopy(payload)
        stale_summary_id["summary_id"] = "transition-summary:" + "0" * 24
        with self.assertRaises(AnalysisV3Error) as raised:
            TRANSITION_SUMMARY_CODEC_V3.decode(stale_summary_id)
        self.assertEqual(raised.exception.code, "stale_record_id")


if __name__ == "__main__":
    unittest.main()
